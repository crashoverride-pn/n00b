/**
 * @file n00b_objfile_emit.c
 * @brief Emit platform-native .o files from compiled module code.
 */

#include "n00b.h"
#include "core/alloc.h"
#include "n00b/n00b_compile_binary.h"
#include "compiler/objfile/writer.h"

#include <string.h>

#ifdef _WIN32

#include "compiler/objfile/pe_types.h"

#define N00B_COFF_REL_AMD64_ADDR64  0x0001
#define N00B_COFF_SYM_TYPE_FUNCTION 0x0020

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} n00b_coff_strtab_t;

static uint32_t
coff_strtab_add(n00b_coff_strtab_t *tab, const char *s)
{
    size_t n = strlen(s) + 1;

    if (tab->len + n > tab->cap) {
        size_t new_cap = tab->cap ? tab->cap * 2 : 256;

        while (new_cap < tab->len + n) {
            new_cap *= 2;
        }

        void *grown = n00b_alloc_array(uint8_t, new_cap);
        if (tab->data) {
            memcpy(grown, tab->data, tab->len);
            n00b_free(tab->data);
        }
        tab->data = grown;
        tab->cap  = new_cap;
    }

    uint32_t off = (uint32_t)(4 + tab->len);
    memcpy(tab->data + tab->len, s, n);
    tab->len += n;
    return off;
}

static void
coff_write_name(n00b_writer_t *w, n00b_coff_strtab_t *strtab, const char *name)
{
    size_t n = strlen(name);

    if (n <= 8) {
        char fixed[8] = {0};

        memcpy(fixed, name, n);
        n00b_writer_write_bytes(w, fixed, sizeof(fixed));
        return;
    }

    n00b_writer_write_u32(w, 0);
    n00b_writer_write_u32(w, coff_strtab_add(strtab, name));
}

static void
coff_write_symbol(n00b_writer_t      *w,
                  n00b_coff_strtab_t *strtab,
                  const char         *name,
                  uint32_t            value,
                  uint16_t            section,
                  uint16_t            type)
{
    coff_write_name(w, strtab, name);
    n00b_writer_write_u32(w, value);
    n00b_writer_write_u16(w, section);
    n00b_writer_write_u16(w, type);
    n00b_writer_write_u8(w, N00B_PE_SYM_CLASS_EXTERNAL);
    n00b_writer_write_u8(w, 0);
}

n00b_buffer_t *
n00b_emit_object_file(n00b_module_code_t *mod)
{
    if (!mod || mod->func_count == 0) {
        return NULL;
    }

    size_t total_code = 0;

    for (size_t i = 0; i < mod->func_count; i++) {
        total_code += mod->funcs[i].code_len;
    }

    if (total_code == 0) {
        return NULL;
    }

    uint8_t *text_data    = n00b_alloc_array(uint8_t, total_code);
    size_t  *func_offsets = n00b_alloc_array(size_t, mod->func_count);
    size_t   off          = 0;

    for (size_t i = 0; i < mod->func_count; i++) {
        func_offsets[i] = off;
        memcpy(text_data + off, mod->funcs[i].code, mod->funcs[i].code_len);
        off += mod->funcs[i].code_len;
    }

    size_t total_relocs = 0;

    for (size_t i = 0; i < mod->func_count; i++) {
        total_relocs += mod->funcs[i].reloc_count;
    }

    if (total_relocs > UINT16_MAX) {
        n00b_free(text_data);
        n00b_free(func_offsets);
        return NULL;
    }

    const char **ext_names = NULL;
    size_t       ext_count = 0;

    if (total_relocs > 0) {
        ext_names = n00b_alloc_array(const char *, total_relocs);

        for (size_t i = 0; i < mod->func_count; i++) {
            for (size_t j = 0; j < mod->funcs[i].reloc_count; j++) {
                const char *sym   = mod->funcs[i].relocs[j].sym;
                bool        found = false;

                for (size_t k = 0; k < ext_count; k++) {
                    if (strcmp(ext_names[k], sym) == 0) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    ext_names[ext_count++] = sym;
                }
            }
        }
    }

    uint32_t file_header_size = N00B_PE_FILE_HEADER_SIZE;
    uint32_t section_size     = N00B_PE_SECTION_HEADER_SIZE;
    uint32_t text_offset      = file_header_size + section_size;
    uint32_t reloc_offset     = text_offset + (uint32_t)total_code;
    uint32_t sym_offset       = reloc_offset + (uint32_t)total_relocs * 10;
    uint32_t nsyms            = (uint32_t)(mod->func_count + ext_count);

    n00b_writer_t     *w      = n00b_writer_new(sym_offset + nsyms * 18 + 256);
    n00b_coff_strtab_t strtab = {0};

    n00b_writer_write_u16(w, N00B_PE_MACHINE_AMD64);
    n00b_writer_write_u16(w, 1);
    n00b_writer_write_u32(w, 0);
    n00b_writer_write_u32(w, sym_offset);
    n00b_writer_write_u32(w, nsyms);
    n00b_writer_write_u16(w, 0);
    n00b_writer_write_u16(w, 0);

    char text_name[8] = {'.', 't', 'e', 'x', 't', 0, 0, 0};

    n00b_writer_write_bytes(w, text_name, sizeof(text_name));
    n00b_writer_write_u32(w, 0);
    n00b_writer_write_u32(w, 0);
    n00b_writer_write_u32(w, (uint32_t)total_code);
    n00b_writer_write_u32(w, text_offset);
    n00b_writer_write_u32(w, total_relocs ? reloc_offset : 0);
    n00b_writer_write_u32(w, 0);
    n00b_writer_write_u16(w, (uint16_t)total_relocs);
    n00b_writer_write_u16(w, 0);
    n00b_writer_write_u32(w,
                          N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_ALIGN_16BYTES
                              | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);

    n00b_writer_write_bytes(w, text_data, total_code);

    for (size_t i = 0; i < mod->func_count; i++) {
        for (size_t j = 0; j < mod->funcs[i].reloc_count; j++) {
            n00b_reloc_t *r       = &mod->funcs[i].relocs[j];
            uint32_t      sym_idx = 0;

            for (size_t k = 0; k < ext_count; k++) {
                if (strcmp(ext_names[k], r->sym) == 0) {
                    sym_idx = (uint32_t)mod->func_count + (uint32_t)k;
                    break;
                }
            }

            uint32_t reloc_va = (uint32_t)(func_offsets[i] + r->offset);

            if ((size_t)reloc_va + 8 <= total_code) {
                n00b_writer_patch_u64(w, (size_t)text_offset + reloc_va, 0);
            }

            n00b_writer_write_u32(w, reloc_va);
            n00b_writer_write_u32(w, sym_idx);
            n00b_writer_write_u16(w, N00B_COFF_REL_AMD64_ADDR64);
        }
    }

    for (size_t i = 0; i < mod->func_count; i++) {
        coff_write_symbol(w,
                          &strtab,
                          mod->funcs[i].name,
                          (uint32_t)func_offsets[i],
                          1,
                          N00B_COFF_SYM_TYPE_FUNCTION);
    }

    for (size_t i = 0; i < ext_count; i++) {
        coff_write_symbol(w, &strtab, ext_names[i], 0, 0, 0);
    }

    n00b_writer_write_u32(w, (uint32_t)(4 + strtab.len));

    if (strtab.len > 0) {
        n00b_writer_write_bytes(w, strtab.data, strtab.len);
    }

    n00b_buffer_t *result = n00b_writer_finalize(w);

    n00b_free(text_data);
    n00b_free(func_offsets);
    n00b_free(ext_names);
    n00b_free(strtab.data);

    return result;
}

#elif defined(__APPLE__)
#include "compiler/objfile/macho.h"
#include "compiler/objfile/macho_build.h"

// Mach-O load command types we need.
#define LC_SEGMENT_64 0x19
#define LC_SYMTAB     0x02
#define LC_DYSYMTAB   0x0B

n00b_buffer_t *
n00b_emit_object_file(n00b_module_code_t *mod)
{
    if (!mod || mod->func_count == 0) {
        return NULL;
    }

    // Concatenate all function code into a single text section.
    size_t total_code = 0;

    for (size_t i = 0; i < mod->func_count; i++) {
        total_code += mod->funcs[i].code_len;
    }

    if (total_code == 0) {
        return NULL;
    }

    // Build concatenated code buffer and compute function offsets.
    uint8_t *text_data    = n00b_alloc_array(uint8_t, total_code);
    size_t  *func_offsets = n00b_alloc_array(size_t, mod->func_count);
    size_t   off          = 0;

    for (size_t i = 0; i < mod->func_count; i++) {
        func_offsets[i] = off;
        memcpy(text_data + off, mod->funcs[i].code, mod->funcs[i].code_len);
        off += mod->funcs[i].code_len;
    }

    // Build string table.
    n00b_strtab_builder_t *strtab = n00b_strtab_builder_new();

    // Count symbols: one per function + one per unique external symbol.
    // First collect unique external symbols.
    size_t total_relocs = 0;

    for (size_t i = 0; i < mod->func_count; i++) {
        total_relocs += mod->funcs[i].reloc_count;
    }

    // Deduplicate external symbol names.
    const char **ext_names  = NULL;
    uint32_t    *ext_stridx = NULL;
    size_t       ext_count  = 0;

    if (total_relocs > 0) {
        ext_names  = n00b_alloc_array(const char *, total_relocs);
        ext_stridx = n00b_alloc_array(uint32_t, total_relocs);

        for (size_t i = 0; i < mod->func_count; i++) {
            for (size_t j = 0; j < mod->funcs[i].reloc_count; j++) {
                const char *sym   = mod->funcs[i].relocs[j].sym;
                bool        found = false;

                for (size_t k = 0; k < ext_count; k++) {
                    if (strcmp(ext_names[k], sym) == 0) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    ext_names[ext_count++] = sym;
                }
            }
        }
    }

    // Add all symbol names to string table.
    // Defined function symbols.
    uint32_t *func_stridx = n00b_alloc_array(uint32_t, mod->func_count);

    for (size_t i = 0; i < mod->func_count; i++) {
        // Mach-O symbols need leading underscore.
        char prefixed[256];
        snprintf(prefixed, sizeof(prefixed), "_%s", mod->funcs[i].name);
        func_stridx[i] = n00b_strtab_builder_add(strtab, prefixed);
    }

    // External (undefined) symbols.
    for (size_t i = 0; i < ext_count; i++) {
        char prefixed[256];
        snprintf(prefixed, sizeof(prefixed), "_%s", ext_names[i]);
        ext_stridx[i] = n00b_strtab_builder_add(strtab, prefixed);
    }

    size_t strtab_size = n00b_strtab_builder_size(strtab);

    // Symbol counts.
    uint32_t n_local  = (uint32_t)mod->func_count; // defined functions
    uint32_t n_extern = (uint32_t)ext_count;       // undefined externals
    uint32_t n_syms   = n_local + n_extern;

    // Layout:
    //   0:                  Mach-O header (32 bytes)
    //   32:                 LC_SEGMENT_64 (72 + 80 = 152 bytes for 1 section)
    //   184:                LC_SYMTAB (24 bytes)
    //   208:                LC_DYSYMTAB (80 bytes)
    //   288:                Section content (text_data, total_code bytes)
    //   288+total_code:     Relocation entries (8 bytes each)
    //   after relocs:       Symbol table (nlist64: 16 bytes each)
    //   after symtab:       String table

    uint32_t header_size       = 32;
    uint32_t lc_segment64_size = 72 + 80; // segment_command_64 + 1 section_64
    uint32_t lc_symtab_size    = 24;
    uint32_t lc_dysymtab_size  = 80;
    uint32_t total_lc_size     = lc_segment64_size + lc_symtab_size + lc_dysymtab_size;

    uint32_t text_offset  = header_size + total_lc_size;
    uint32_t reloc_offset = text_offset + (uint32_t)total_code;
    uint32_t nreloc       = (uint32_t)total_relocs;
    uint32_t sym_offset   = reloc_offset + nreloc * 8;
    uint32_t str_offset   = sym_offset + n_syms * 16;

    n00b_writer_t *w = n00b_writer_new(str_offset + strtab_size + 256);

    // --- Mach-O header ---
    n00b_writer_write_u32(w, MH_MAGIC_64);
#if defined(__aarch64__) || defined(__arm64__)
    n00b_writer_write_u32(w, (uint32_t)CPU_TYPE_ARM64);
    n00b_writer_write_u32(w, CPU_SUBTYPE_ARM64_ALL);
#else
    n00b_writer_write_u32(w, (uint32_t)CPU_TYPE_X86_64);
    n00b_writer_write_u32(w, CPU_SUBTYPE_X86_64_ALL);
#endif
    n00b_writer_write_u32(w, MH_OBJECT);                  // filetype
    n00b_writer_write_u32(w, 3);                          // ncmds
    n00b_writer_write_u32(w, total_lc_size);              // sizeofcmds
    n00b_writer_write_u32(w, MH_SUBSECTIONS_VIA_SYMBOLS); // flags
    n00b_writer_write_u32(w, 0);                          // reserved (64-bit only)

    // --- LC_SEGMENT_64 ---
    n00b_writer_write_u32(w, LC_SEGMENT_64);     // cmd
    n00b_writer_write_u32(w, lc_segment64_size); // cmdsize
    n00b_writer_write_bytes(w,
                            "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                            16);           // segname (empty for MH_OBJECT)
    n00b_writer_write_u64(w, 0);           // vmaddr
    n00b_writer_write_u64(w, total_code);  // vmsize
    n00b_writer_write_u64(w, text_offset); // fileoff
    n00b_writer_write_u64(w, total_code);  // filesize
    n00b_writer_write_u32(w, 7);           // maxprot (rwx)
    n00b_writer_write_u32(w, 5);           // initprot (rx)
    n00b_writer_write_u32(w, 1);           // nsects
    n00b_writer_write_u32(w, 0);           // flags

    // section_64 header: __text, __TEXT
    char sectname[16] = "__text";
    char segname[16]  = "__TEXT";

    n00b_writer_write_bytes(w, sectname, 16);
    n00b_writer_write_bytes(w, segname, 16);
    n00b_writer_write_u64(w, 0);                             // addr
    n00b_writer_write_u64(w, total_code);                    // size
    n00b_writer_write_u32(w, text_offset);                   // offset
    n00b_writer_write_u32(w, 4);                             // align (2^4 = 16)
    n00b_writer_write_u32(w, nreloc > 0 ? reloc_offset : 0); // reloff
    n00b_writer_write_u32(w, nreloc);                        // nreloc
    n00b_writer_write_u32(w,
                          S_REGULAR | S_ATTR_SOME_INSTRUCTIONS
                              | S_ATTR_PURE_INSTRUCTIONS); // flags
    n00b_writer_write_u32(w, 0);                           // reserved1
    n00b_writer_write_u32(w, 0);                           // reserved2
    n00b_writer_write_u32(w, 0);                           // reserved3 (padding)

    // --- LC_SYMTAB ---
    n00b_writer_write_u32(w, LC_SYMTAB);
    n00b_writer_write_u32(w, lc_symtab_size);
    n00b_writer_write_u32(w, sym_offset);            // symoff
    n00b_writer_write_u32(w, n_syms);                // nsyms
    n00b_writer_write_u32(w, str_offset);            // stroff
    n00b_writer_write_u32(w, (uint32_t)strtab_size); // strsize

    // --- LC_DYSYMTAB ---
    n00b_writer_write_u32(w, LC_DYSYMTAB);
    n00b_writer_write_u32(w, lc_dysymtab_size);
    n00b_writer_write_u32(w, 0);        // ilocalsym
    n00b_writer_write_u32(w, n_local);  // nlocalsym
    n00b_writer_write_u32(w, n_local);  // iextdefsym
    n00b_writer_write_u32(w, 0);        // nextdefsym
    n00b_writer_write_u32(w, n_local);  // iundefsym
    n00b_writer_write_u32(w, n_extern); // nundefsym
    n00b_writer_write_u32(w, 0);        // tocoff
    n00b_writer_write_u32(w, 0);        // ntoc
    n00b_writer_write_u32(w, 0);        // modtaboff
    n00b_writer_write_u32(w, 0);        // nmodtab
    n00b_writer_write_u32(w, 0);        // extrefsymoff
    n00b_writer_write_u32(w, 0);        // nextrefsyms
    n00b_writer_write_u32(w, 0);        // indirectsymoff
    n00b_writer_write_u32(w, 0);        // nindirectsyms
    n00b_writer_write_u32(w, 0);        // extreloff
    n00b_writer_write_u32(w, 0);        // nextrel
    n00b_writer_write_u32(w, 0);        // locreloff
    n00b_writer_write_u32(w, 0);        // nlocrel

    // --- Section content (text) ---
    n00b_writer_write_bytes(w, text_data, total_code);

    // --- Relocation entries ---
    // Mach-O relocation_info: { int32_t r_address; uint32_t packed; }
    for (size_t i = 0; i < mod->func_count; i++) {
        for (size_t j = 0; j < mod->funcs[i].reloc_count; j++) {
            n00b_reloc_t *r    = &mod->funcs[i].relocs[j];
            int32_t       addr = (int32_t)(func_offsets[i] + r->offset);

            // Find the external symbol index.
            uint32_t sym_idx = 0;

            for (size_t k = 0; k < ext_count; k++) {
                if (strcmp(ext_names[k], r->sym) == 0) {
                    sym_idx = n_local + (uint32_t)k;
                    break;
                }
            }

            // Pack relocation: symbolnum(24) | pcrel(1) | length(2) | extern(1) | type(4)
            uint32_t packed = (sym_idx & 0x00FFFFFF) | (0u << 24) // pcrel = 0
                            | (3u << 25)                          // length = 3 (8 bytes)
                            | (1u << 27)                          // extern = 1
#if defined(__aarch64__) || defined(__arm64__)
                            | ((uint32_t)ARM64_RELOC_UNSIGNED << 28);
#else
                            | ((uint32_t)X86_64_RELOC_UNSIGNED << 28);
#endif

            n00b_writer_write_i32(w, addr);
            n00b_writer_write_u32(w, packed);
        }
    }

    // --- Symbol table (nlist_64) ---
    // Defined function symbols first (N_SECT | N_EXT, section 1).
    for (size_t i = 0; i < mod->func_count; i++) {
        n00b_writer_write_u32(w, func_stridx[i]);  // n_strx
        n00b_writer_write_u8(w, N_SECT | N_EXT);   // n_type
        n00b_writer_write_u8(w, 1);                // n_sect (1-based)
        n00b_writer_write_u16(w, 0);               // n_desc
        n00b_writer_write_u64(w, func_offsets[i]); // n_value
    }

    // Undefined external symbols.
    for (size_t i = 0; i < ext_count; i++) {
        n00b_writer_write_u32(w, ext_stridx[i]); // n_strx
        n00b_writer_write_u8(w, N_UNDF | N_EXT); // n_type
        n00b_writer_write_u8(w, 0);              // n_sect
        n00b_writer_write_u16(w, 0);             // n_desc
        n00b_writer_write_u64(w, 0);             // n_value
    }

    // --- String table ---
    n00b_strtab_builder_write(strtab, w);

    n00b_buffer_t *result = n00b_writer_finalize(w);

    n00b_free(text_data);
    n00b_free(func_offsets);
    n00b_free(func_stridx);
    n00b_free(ext_names);
    n00b_free(ext_stridx);

    return result;
}

#else // Linux / ELF

#include "compiler/objfile/elf.h"
#include "compiler/objfile/elf_build.h"

n00b_buffer_t *
n00b_emit_object_file(n00b_module_code_t *mod)
{
    if (!mod || mod->func_count == 0) {
        return NULL;
    }

    // Concatenate all function code.
    size_t total_code = 0;

    for (size_t i = 0; i < mod->func_count; i++) {
        total_code += mod->funcs[i].code_len;
    }

    if (total_code == 0) {
        return NULL;
    }

    uint8_t *text_data    = n00b_alloc_array(uint8_t, total_code);
    size_t  *func_offsets = n00b_alloc_array(size_t, mod->func_count);
    size_t   off          = 0;

    for (size_t i = 0; i < mod->func_count; i++) {
        func_offsets[i] = off;
        memcpy(text_data + off, mod->funcs[i].code, mod->funcs[i].code_len);
        off += mod->funcs[i].code_len;
    }

#if defined(__aarch64__) || defined(__arm64__)
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_REL, EM_AARCH64);
#else
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_REL, EM_X86_64);
#endif

    // Add .text section.
    n00b_elf_section_t *text
        = n00b_elf_add_section(bin, ".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR);
    text->content = n00b_buffer_from_bytes((char *)text_data, total_code);

    uint16_t text_shndx = n00b_elf_section_index(bin, ".text");

    // Add defined function symbols.
    // First add the mandatory null symbol.
    n00b_elf_add_symtab_symbol(bin, "", 0, 0, STB_LOCAL, STT_NOTYPE, SHN_UNDEF);

    for (size_t i = 0; i < mod->func_count; i++) {
        n00b_elf_add_symtab_symbol(bin,
                                   mod->funcs[i].name,
                                   func_offsets[i],
                                   mod->funcs[i].code_len,
                                   STB_GLOBAL,
                                   STT_FUNC,
                                   text_shndx);
    }

    // Collect unique external symbols and add as undefined.
    size_t total_relocs = 0;

    for (size_t i = 0; i < mod->func_count; i++) {
        total_relocs += mod->funcs[i].reloc_count;
    }

    const char **ext_names  = NULL;
    uint32_t    *ext_symidx = NULL;
    size_t       ext_count  = 0;

    if (total_relocs > 0) {
        ext_names  = n00b_alloc_array(const char *, total_relocs);
        ext_symidx = n00b_alloc_array(uint32_t, total_relocs);

        for (size_t i = 0; i < mod->func_count; i++) {
            for (size_t j = 0; j < mod->funcs[i].reloc_count; j++) {
                const char *sym   = mod->funcs[i].relocs[j].sym;
                bool        found = false;

                for (size_t k = 0; k < ext_count; k++) {
                    if (strcmp(ext_names[k], sym) == 0) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    ext_names[ext_count]  = sym;
                    // Symbol index: 1 (null) + func_count + ext_count
                    ext_symidx[ext_count] = 1 + (uint32_t)mod->func_count + (uint32_t)ext_count;
                    ext_count++;
                }
            }
        }

        for (size_t i = 0; i < ext_count; i++) {
            n00b_elf_add_symtab_symbol(bin,
                                       ext_names[i],
                                       0,
                                       0,
                                       STB_GLOBAL,
                                       STT_NOTYPE,
                                       SHN_UNDEF);
        }
    }

    // Add relocations.
    for (size_t i = 0; i < mod->func_count; i++) {
        for (size_t j = 0; j < mod->funcs[i].reloc_count; j++) {
            n00b_reloc_t *r         = &mod->funcs[i].relocs[j];
            uint64_t      reloc_off = func_offsets[i] + r->offset;

            // Find external symbol index.
            uint32_t sym_idx = 0;

            for (size_t k = 0; k < ext_count; k++) {
                if (strcmp(ext_names[k], r->sym) == 0) {
                    sym_idx = ext_symidx[k];
                    break;
                }
            }

#if defined(__aarch64__) || defined(__arm64__)
            n00b_elf_add_relocation(bin, reloc_off, sym_idx, R_AARCH64_ABS64, 0);
#else
            n00b_elf_add_relocation(bin, reloc_off, sym_idx, R_X86_64_64, 0);
#endif
        }
    }

    auto r = n00b_elf_build(bin);

    n00b_free(text_data);
    n00b_free(func_offsets);
    n00b_free(ext_names);
    n00b_free(ext_symidx);

    if (n00b_result_is_err(r)) {
        return NULL;
    }

    return n00b_result_get(r);
}

#endif // Windows vs macOS vs Linux

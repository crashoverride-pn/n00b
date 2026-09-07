#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "compiler/objfile/elf.h"

// ============================================================================
// Helper: write little-endian values at a byte pointer
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

static void
puti64(uint8_t *p, int64_t v)
{
    memcpy(p, &v, 8);
}

// ============================================================================
// Helper: write a minimal ELF64 header
// ============================================================================

static void
write_elf64_header(uint8_t *p,
                   uint64_t phoff,
                   uint16_t phnum,
                   uint64_t shoff,
                   uint16_t shnum,
                   uint16_t shstrndx)
{
    // e_ident
    p[0] = 0x7f; p[1] = 'E'; p[2] = 'L'; p[3] = 'F';
    p[EI_CLASS]   = ELFCLASS64;
    p[EI_DATA]    = ELFDATA2LSB;
    p[EI_VERSION] = EV_CURRENT;

    put16(p + 16, ET_EXEC);       // e_type
    put16(p + 18, EM_X86_64);     // e_machine
    put32(p + 20, EV_CURRENT);    // e_version
    put64(p + 24, 0x401000);      // e_entry
    put64(p + 32, phoff);         // e_phoff
    put64(p + 40, shoff);         // e_shoff
    // e_flags = 0
    put16(p + 52, 64);            // e_ehsize
    put16(p + 54, 56);            // e_phentsize
    put16(p + 56, phnum);         // e_phnum
    put16(p + 58, 64);            // e_shentsize
    put16(p + 60, shnum);         // e_shnum
    put16(p + 62, shstrndx);      // e_shstrndx
}

// ============================================================================
// Helper: write a program header
// ============================================================================

static void
write_phdr(uint8_t *p,
           uint32_t type,
           uint32_t flags,
           uint64_t offset,
           uint64_t vaddr,
           uint64_t filesz,
           uint64_t memsz,
           uint64_t align)
{
    put32(p + 0,  type);
    put32(p + 4,  flags);
    put64(p + 8,  offset);
    put64(p + 16, vaddr);
    put64(p + 24, vaddr);   // paddr = vaddr
    put64(p + 32, filesz);
    put64(p + 40, memsz);
    put64(p + 48, align);
}

// ============================================================================
// Helper: write a section header
// ============================================================================

static void
write_shdr(uint8_t *p,
           uint32_t name,
           uint32_t type,
           uint64_t flags,
           uint64_t addr,
           uint64_t offset,
           uint64_t size,
           uint32_t link,
           uint32_t info,
           uint64_t addralign,
           uint64_t entsize)
{
    put32(p + 0,  name);
    put32(p + 4,  type);
    put64(p + 8,  flags);
    put64(p + 16, addr);
    put64(p + 24, offset);
    put64(p + 32, size);
    put32(p + 40, link);
    put32(p + 44, info);
    put64(p + 48, addralign);
    put64(p + 56, entsize);
}

// ============================================================================
// Helper: build a minimal synthetic ELF64 binary (original)
// ============================================================================

static n00b_buffer_t *
make_minimal_elf64(void)
{
    size_t total_size = 320;

    n00b_buffer_t *buf = n00b_buffer_new(total_size);
    memset(buf->data, 0, total_size);
    buf->byte_len = total_size;

    uint8_t *p = (uint8_t *)buf->data;

    // ELF header
    write_elf64_header(p, 64, 1, 120, 2, 1);

    // 1 PT_LOAD segment at offset 64
    write_phdr(p + 64, PT_LOAD, PF_R | PF_X, 0, 0x400000,
               total_size, total_size, 0x1000);

    // Section header 0: SHT_NULL (at offset 120) — already zeroed.

    // Section header 1: .shstrtab (at offset 184)
    // shstrtab content at offset 248: "\0.shstrtab\0"
    write_shdr(p + 184,
               1,           // sh_name = 1 (index into shstrtab)
               SHT_STRTAB,  // sh_type
               0, 0,        // flags, addr
               248,          // sh_offset
               11,           // sh_size = strlen("\0.shstrtab\0")
               0, 0,        // link, info
               1, 0);       // addralign, entsize

    // .shstrtab content
    uint8_t *strtab = p + 248;
    strtab[0] = '\0';
    memcpy(strtab + 1, ".shstrtab", 9);
    strtab[10] = '\0';

    return buf;
}

// ============================================================================
// Helper: ELF64 with symbol table
// ============================================================================

static n00b_buffer_t *
make_elf64_with_symbols(void)
{
    // Layout:
    //   [0]    ELF header             64 bytes
    //   [64]   PT_LOAD phdr           56 bytes
    //   [120]  Section headers:       4 * 64 = 256 bytes
    //          [0] SHT_NULL
    //          [1] .shstrtab
    //          [2] .strtab
    //          [3] .symtab
    //   [376]  .shstrtab content      28 bytes: \0.shstrtab\0.strtab\0.symtab\0
    //   [404]  .strtab content        16 bytes: \0my_func\0my_var\0
    //   [420]  .symtab content        3 * 24 = 72 bytes
    //   Total: 492, round to 512

    size_t total_size = 512;
    n00b_buffer_t *buf = n00b_buffer_new(total_size);
    memset(buf->data, 0, total_size);
    buf->byte_len = total_size;
    uint8_t *p = (uint8_t *)buf->data;

    uint64_t shoff = 120;

    write_elf64_header(p, 64, 1, shoff, 4, 1);

    // PT_LOAD segment covering entire file
    write_phdr(p + 64, PT_LOAD, PF_R | PF_X, 0, 0x400000,
               total_size, total_size, 0x1000);

    // --- Section headers at offset 120 ---
    uint8_t *sh = p + shoff;

    // [0] SHT_NULL — already zeroed

    // .shstrtab content: "\0.shstrtab\0.strtab\0.symtab\0"
    //   offsets:  0:\0  1:.shstrtab  11:\0  12:.strtab  19:\0  20:.symtab  27:\0
    size_t shstrtab_off = 376;
    size_t shstrtab_sz  = 28;
    uint8_t *shstr = p + shstrtab_off;
    shstr[0] = '\0';
    memcpy(shstr + 1, ".shstrtab", 9);
    shstr[10] = '\0';
    memcpy(shstr + 11, ".strtab", 7);
    shstr[18] = '\0';
    memcpy(shstr + 19, ".symtab", 7);
    shstr[26] = '\0';
    // Extra byte at 27 for safety
    shstr[27] = '\0';

    // [1] .shstrtab
    write_shdr(sh + 64,
               1,             // sh_name = 1 (".shstrtab" starts at index 1)
               SHT_STRTAB,
               0, 0,
               shstrtab_off,
               shstrtab_sz,
               0, 0, 1, 0);

    // .strtab content: "\0my_func\0my_var\0"
    //   offsets: 0:\0  1:my_func  9:\0  10:my_var  16:\0 (wait, "my_var" is 6 chars)
    //   Actually: \0 m y _ f u n c \0 m y _ v a r \0
    //             0  1 2 3 4 5 6 7  8  9 10 11 12 13 14 15
    size_t strtab_off = 404;
    size_t strtab_sz  = 16;
    uint8_t *str = p + strtab_off;
    str[0] = '\0';
    memcpy(str + 1, "my_func", 7);
    str[8] = '\0';
    memcpy(str + 9, "my_var", 6);
    str[15] = '\0';

    // [2] .strtab
    write_shdr(sh + 128,
               11,            // sh_name = 11 (".strtab" starts at index 11)
               SHT_STRTAB,
               0, 0,
               strtab_off,
               strtab_sz,
               0, 0, 1, 0);

    // .symtab content: 3 entries, each 24 bytes
    //   [0] null symbol (all zeros)
    //   [1] "my_func": st_name=1, st_info=STT_FUNC|STB_GLOBAL, st_other=0,
    //       st_shndx=1, st_value=0x401000, st_size=64
    //   [2] "my_var":  st_name=9, st_info=STT_OBJECT|STB_GLOBAL, st_other=0,
    //       st_shndx=1, st_value=0x402000, st_size=8

    size_t symtab_off = 420;
    size_t symtab_sz  = 3 * 24;
    uint8_t *sym = p + symtab_off;

    // [0] null symbol — already zeroed

    // [1] my_func
    uint8_t *s1 = sym + 24;
    put32(s1 + 0, 1);                                      // st_name
    s1[4] = N00B_ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);           // st_info
    s1[5] = 0;                                              // st_other
    put16(s1 + 6, 1);                                       // st_shndx
    put64(s1 + 8, 0x401000);                                // st_value
    put64(s1 + 16, 64);                                     // st_size

    // [2] my_var
    uint8_t *s2 = sym + 48;
    put32(s2 + 0, 9);                                       // st_name
    s2[4] = N00B_ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);          // st_info
    s2[5] = 0;                                               // st_other
    put16(s2 + 6, 1);                                        // st_shndx
    put64(s2 + 8, 0x402000);                                 // st_value
    put64(s2 + 16, 8);                                       // st_size

    // [3] .symtab section header
    write_shdr(sh + 192,
               19,            // sh_name = 19 (".symtab" starts at index 19)
               SHT_SYMTAB,
               0, 0,
               symtab_off,
               symtab_sz,
               2,             // sh_link = 2 (index of .strtab)
               1,             // sh_info = 1 (index of first non-local symbol)
               8, 24);        // addralign, entsize

    return buf;
}

// ============================================================================
// Helper: ELF64 with dynamic table
// ============================================================================

static n00b_buffer_t *
make_elf64_with_dynamic(void)
{
    // Layout:
    //   [0]    ELF header               64 bytes
    //   [64]   PT_LOAD phdr             56 bytes
    //   [120]  PT_DYNAMIC phdr          56 bytes
    //   [176]  Section headers:         3 * 64 = 192 bytes
    //          [0] SHT_NULL
    //          [1] .shstrtab
    //          [2] .dynamic
    //   [368]  .shstrtab content        20 bytes: \0.shstrtab\0.dynamic\0
    //   [388]  .dynamic content         5 * 16 = 80 bytes
    //   Total: 468, round to 512

    size_t total_size = 512;
    n00b_buffer_t *buf = n00b_buffer_new(total_size);
    memset(buf->data, 0, total_size);
    buf->byte_len = total_size;
    uint8_t *p = (uint8_t *)buf->data;

    write_elf64_header(p, 64, 2, 176, 3, 1);

    // PT_LOAD
    write_phdr(p + 64, PT_LOAD, PF_R | PF_X, 0, 0x400000,
               total_size, total_size, 0x1000);

    // .dynamic content at offset 388
    size_t dyn_off = 388;
    size_t dyn_sz  = 5 * 16;

    // PT_DYNAMIC
    write_phdr(p + 120, PT_DYNAMIC, PF_R | PF_W, dyn_off, 0x400000 + dyn_off,
               dyn_sz, dyn_sz, 8);

    // --- Section headers at offset 176 ---
    uint8_t *sh = p + 176;

    // .shstrtab: "\0.shstrtab\0.dynamic\0"
    //   offsets: 0:\0 1:.shstrtab 11:.dynamic 20:\0
    size_t shstrtab_off = 368;
    size_t shstrtab_sz  = 20;
    uint8_t *shstr = p + shstrtab_off;
    shstr[0] = '\0';
    memcpy(shstr + 1, ".shstrtab", 9);
    shstr[10] = '\0';
    memcpy(shstr + 11, ".dynamic", 8);
    shstr[19] = '\0';

    // [1] .shstrtab
    write_shdr(sh + 64,
               1, SHT_STRTAB, 0, 0,
               shstrtab_off, shstrtab_sz,
               0, 0, 1, 0);

    // [2] .dynamic
    write_shdr(sh + 128,
               11, SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE, 0x400000 + dyn_off,
               dyn_off, dyn_sz,
               0, 0, 8, 16);

    // Dynamic entries: tag (8 bytes) + value (8 bytes) each
    uint8_t *dyn = p + dyn_off;
    // [0] DT_NEEDED, value = 1 (string table offset)
    puti64(dyn + 0, DT_NEEDED);
    put64(dyn + 8, 1);
    // [1] DT_STRTAB
    puti64(dyn + 16, DT_STRTAB);
    put64(dyn + 24, 0x400000);
    // [2] DT_STRSZ
    puti64(dyn + 32, DT_STRSZ);
    put64(dyn + 40, 16);
    // [3] DT_SYMTAB
    puti64(dyn + 48, DT_SYMTAB);
    put64(dyn + 56, 0x400100);
    // [4] DT_NULL
    puti64(dyn + 64, DT_NULL);
    put64(dyn + 72, 0);

    return buf;
}

// ============================================================================
// Helper: ELF64 with notes
// ============================================================================

static n00b_buffer_t *
make_elf64_with_notes(void)
{
    // Layout:
    //   [0]    ELF header               64 bytes
    //   [64]   PT_LOAD phdr             56 bytes
    //   [120]  PT_NOTE phdr             56 bytes
    //   [176]  Section headers:         3 * 64 = 192 bytes
    //          [0] SHT_NULL
    //          [1] .shstrtab
    //          [2] .note.gnu.abi-tag
    //   [368]  .shstrtab content        30 bytes: \0.shstrtab\0.note.gnu.abi-tag\0
    //   [400]  note content:            12 (header) + 4 (name "GNU\0") + 16 (desc) = 32
    //   Total: 432, round to 512

    size_t total_size = 512;
    n00b_buffer_t *buf = n00b_buffer_new(total_size);
    memset(buf->data, 0, total_size);
    buf->byte_len = total_size;
    uint8_t *p = (uint8_t *)buf->data;

    write_elf64_header(p, 64, 2, 176, 3, 1);

    // PT_LOAD
    write_phdr(p + 64, PT_LOAD, PF_R | PF_X, 0, 0x400000,
               total_size, total_size, 0x1000);

    size_t note_off = 400;
    size_t note_sz  = 32; // 12-byte header + 4-byte name + 16-byte desc

    // PT_NOTE
    write_phdr(p + 120, PT_NOTE, PF_R, note_off, 0x400000 + note_off,
               note_sz, note_sz, 4);

    // --- Section headers at offset 176 ---
    uint8_t *sh = p + 176;

    // .shstrtab: "\0.shstrtab\0.note.gnu.abi-tag\0"
    size_t shstrtab_off = 368;
    uint8_t *shstr = p + shstrtab_off;
    shstr[0] = '\0';
    memcpy(shstr + 1, ".shstrtab", 9);
    shstr[10] = '\0';
    memcpy(shstr + 11, ".note.gnu.abi-tag", 17);
    shstr[28] = '\0';
    size_t shstrtab_sz = 29;

    // [1] .shstrtab
    write_shdr(sh + 64,
               1, SHT_STRTAB, 0, 0,
               shstrtab_off, shstrtab_sz,
               0, 0, 1, 0);

    // [2] .note.gnu.abi-tag
    write_shdr(sh + 128,
               11, SHT_NOTE, SHF_ALLOC, 0x400000 + note_off,
               note_off, note_sz,
               0, 0, 4, 0);

    // Note content: n_namesz=4, n_descsz=16, n_type=NT_GNU_ABI_TAG(1)
    uint8_t *note = p + note_off;
    put32(note + 0, 4);               // n_namesz = 4 ("GNU\0")
    put32(note + 4, 16);              // n_descsz
    put32(note + 8, NT_GNU_ABI_TAG);  // n_type
    memcpy(note + 12, "GNU", 3);
    note[15] = '\0';
    // desc is 16 bytes of zeros (already zeroed), represents ABI tag data

    return buf;
}

// ============================================================================
// Helper: ELF64 with relocations
// ============================================================================

static n00b_buffer_t *
make_elf64_with_relocations(void)
{
    // Layout:
    //   [0]    ELF header               64 bytes
    //   [64]   PT_LOAD phdr             56 bytes
    //   [120]  Section headers:         4 * 64 = 256 bytes
    //          [0] SHT_NULL
    //          [1] .shstrtab
    //          [2] .strtab
    //          [3] .rela.text
    //   [376]  .shstrtab content        30 bytes: \0.shstrtab\0.strtab\0.rela.text\0
    //   [406]  .strtab content          1 byte: \0
    //   [408]  .rela.text content       2 * 24 = 48 bytes
    //   Total: 456, round to 512

    size_t total_size = 512;
    n00b_buffer_t *buf = n00b_buffer_new(total_size);
    memset(buf->data, 0, total_size);
    buf->byte_len = total_size;
    uint8_t *p = (uint8_t *)buf->data;

    write_elf64_header(p, 64, 1, 120, 4, 1);

    // PT_LOAD
    write_phdr(p + 64, PT_LOAD, PF_R | PF_X, 0, 0x400000,
               total_size, total_size, 0x1000);

    uint8_t *sh = p + 120;

    // .shstrtab: "\0.shstrtab\0.strtab\0.rela.text\0"
    //   0:\0 1:.shstrtab 11:.strtab 19:.rela.text 30:\0
    size_t shstrtab_off = 376;
    size_t shstrtab_sz  = 30;
    uint8_t *shstr = p + shstrtab_off;
    shstr[0] = '\0';
    memcpy(shstr + 1, ".shstrtab", 9);
    shstr[10] = '\0';
    memcpy(shstr + 11, ".strtab", 7);
    shstr[18] = '\0';
    memcpy(shstr + 19, ".rela.text", 10);
    shstr[29] = '\0';

    // [1] .shstrtab
    write_shdr(sh + 64,
               1, SHT_STRTAB, 0, 0,
               shstrtab_off, shstrtab_sz,
               0, 0, 1, 0);

    // .strtab: just "\0"
    size_t strtab_off = 406;
    p[strtab_off] = '\0';

    // [2] .strtab
    write_shdr(sh + 128,
               11, SHT_STRTAB, 0, 0,
               strtab_off, 1,
               0, 0, 1, 0);

    // .rela.text: 2 entries
    size_t rela_off = 408;
    size_t rela_sz  = 2 * 24;
    uint8_t *rela = p + rela_off;

    // [0] offset=0x401000, info=R_X86_64_64 (sym=0, type=1), addend=0
    put64(rela + 0, 0x401000);
    put64(rela + 8, N00B_ELF64_R_INFO(0, R_X86_64_64));
    puti64(rela + 16, 0);

    // [1] offset=0x401008, info=R_X86_64_PC32 (sym=0, type=2), addend=-4
    put64(rela + 24, 0x401008);
    put64(rela + 32, N00B_ELF64_R_INFO(0, R_X86_64_PC32));
    puti64(rela + 40, -4);

    // [3] .rela.text
    write_shdr(sh + 192,
               19, SHT_RELA, 0, 0,
               rela_off, rela_sz,
               2,             // sh_link = .strtab index
               0,             // sh_info
               8, 24);        // addralign, entsize

    return buf;
}

// ============================================================================
// Test: parse synthetic ELF64
// ============================================================================

static void
test_parse_synthetic_elf64(void)
{
    n00b_buffer_t *buf = make_minimal_elf64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_elf_parse(s);

    assert(n00b_result_is_ok(r));

    n00b_elf_binary_t *bin = n00b_result_get(r);

    // Verify header.
    assert(bin->header.ident[0] == 0x7f);
    assert(bin->header.ident[1] == 'E');
    assert(bin->header.ident[2] == 'L');
    assert(bin->header.ident[3] == 'F');
    assert(bin->header.ident[EI_CLASS] == ELFCLASS64);
    assert(bin->header.ident[EI_DATA] == ELFDATA2LSB);
    assert(bin->header.type == ET_EXEC);
    assert(bin->header.machine == EM_X86_64);
    assert(bin->header.entry == 0x401000);
    assert(bin->header.phnum == 1);
    assert(bin->header.shnum == 2);

    // Verify sections.
    assert(bin->num_sections == 2);
    assert(bin->sections[0].type == SHT_NULL);
    assert(bin->sections[1].type == SHT_STRTAB);

    // Verify the .shstrtab name was resolved.
    n00b_string_t *shstrtab_name = bin->sections[1].name;
    const char    *name_cstr     = shstrtab_name->data;

    assert(strcmp(name_cstr, ".shstrtab") == 0);

    // Verify segments.
    assert(bin->num_segments == 1);
    assert(bin->segments[0].type == PT_LOAD);
    assert(bin->segments[0].flags == (PF_R | PF_X));
    assert(bin->segments[0].vaddr == 0x400000);

    printf("  [PASS] parse_synthetic_elf64\n");
}

// ============================================================================
// Test: parse invalid ELF (bad magic)
// ============================================================================

static void
test_parse_bad_magic(void)
{
    uint8_t bad_data[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    n00b_buffer_t *buf = n00b_buffer_from_bytes((char *)bad_data,
                                                sizeof(bad_data));
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_elf_parse(s);

    assert(n00b_result_is_err(r));

    printf("  [PASS] parse_bad_magic\n");
}

// ============================================================================
// Test: parse 32-bit ELF should fail (not supported)
// ============================================================================

static void
test_parse_elf32_rejected(void)
{
    uint8_t data[64] = {};

    data[0] = 0x7f; data[1] = 'E'; data[2] = 'L'; data[3] = 'F';
    data[EI_CLASS]   = ELFCLASS32;
    data[EI_DATA]    = ELFDATA2LSB;
    data[EI_VERSION] = EV_CURRENT;

    n00b_buffer_t *buf = n00b_buffer_from_bytes((char *)data, sizeof(data));
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_elf_parse(s);

    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_ERR_NOT_SUPPORTED);

    printf("  [PASS] parse_elf32_rejected\n");
}

// ============================================================================
// Test: parse truncated ELF
// ============================================================================

static void
test_parse_truncated(void)
{
    // Only magic, too short for full header.
    uint8_t data[] = {0x7f, 'E', 'L', 'F', ELFCLASS64, ELFDATA2LSB, EV_CURRENT, 0};

    n00b_buffer_t *buf = n00b_buffer_from_bytes((char *)data, sizeof(data));
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_elf_parse(s);

    assert(n00b_result_is_err(r));

    printf("  [PASS] parse_truncated\n");
}

// ============================================================================
// Test: parse real binary (/usr/bin/true on Linux)
// ============================================================================

static void
test_parse_real_binary(void)
{
    auto stream_r = n00b_bstream_from_file("/usr/bin/true");

    if (n00b_result_is_err(stream_r)) {
        // Try another common path.
        stream_r = n00b_bstream_from_file("/bin/true");

        if (n00b_result_is_err(stream_r)) {
            printf("  [SKIP] parse_real_binary (no ELF binary found)\n");
            return;
        }
    }

    n00b_bstream_t *s = n00b_result_get(stream_r);

    // Check if it's actually an ELF (skip on macOS where it's MachO).
    if (n00b_buffer_len(s->buf) < 4) {
        printf("  [SKIP] parse_real_binary (file too small)\n");
        return;
    }

    const uint8_t *magic = (const uint8_t *)s->buf->data;

    if (magic[0] != 0x7f || magic[1] != 'E'
        || magic[2] != 'L' || magic[3] != 'F') {
        printf("  [SKIP] parse_real_binary (not ELF, probably macOS)\n");
        return;
    }

    auto r = n00b_elf_parse(s);

    assert(n00b_result_is_ok(r));

    n00b_elf_binary_t *bin = n00b_result_get(r);

    // Basic checks.
    assert(bin->header.ident[0] == 0x7f);
    assert(bin->header.ident[EI_CLASS] == ELFCLASS64);
    assert(bin->header.machine == EM_X86_64
           || bin->header.machine == EM_AARCH64);
    assert(bin->header.type == ET_EXEC || bin->header.type == ET_DYN);

    // Should have segments.
    assert(bin->num_segments > 0);

    // Should have sections (typically).
    assert(bin->num_sections > 0);

    // Should have an entry point.
    assert(bin->header.entry != 0);

    // Dynamic binaries should have dynamic entries.
    if (bin->header.type == ET_DYN || bin->num_dynamic > 0) {
        printf("    dynamic_entries: %u\n", bin->num_dynamic);
    }

    // Query API spot-checks on real binary.
    n00b_option_t(n00b_elf_segment_t *) load_opt
        = n00b_elf_segment_by_type(bin, PT_LOAD);
    assert(n00b_option_is_set(load_opt));

    if (bin->num_symtab > 0 || bin->num_dynsym > 0) {
        printf("    symtab: %u, dynsym: %u\n",
               bin->num_symtab, bin->num_dynsym);
    }

    if (bin->num_dynamic > 0) {
        assert(n00b_option_is_set(n00b_elf_dynamic_by_tag(bin, DT_NULL)));
    }

    if (n00b_elf_has_interpreter(bin)) {
        printf("    interpreter: %s\n", bin->interpreter->data);
    }

    // Print some info.
    printf("    machine: %u, type: %u, entry: 0x%llx\n",
           bin->header.machine, bin->header.type,
           (unsigned long long)bin->header.entry);
    printf("    sections: %u, segments: %u\n",
           bin->num_sections, bin->num_segments);
    printf("    relocations: %u, notes: %u\n",
           bin->num_relocations, bin->num_notes);

    printf("  [PASS] parse_real_binary\n");
}

// ============================================================================
// Test: null stream rejected
// ============================================================================

static void
test_null_stream(void)
{
    auto r = n00b_elf_parse(nullptr);

    assert(n00b_result_is_err(r));

    printf("  [PASS] null_stream\n");
}

// ============================================================================
// Test: symtab parsing
// ============================================================================

static void
test_symtab_parsing(void)
{
    n00b_buffer_t *buf = make_elf64_with_symbols();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_elf_binary_t *bin = n00b_result_get(r);

    // Should have 3 symtab symbols (including null).
    assert(bin->num_symtab == 3);

    // [0] null symbol
    assert(bin->symtab_symbols[0].value == 0);

    // [1] my_func
    assert(strcmp(bin->symtab_symbols[1].name->data, "my_func") == 0);
    assert(N00B_ELF64_ST_TYPE(bin->symtab_symbols[1].info) == STT_FUNC);
    assert(bin->symtab_symbols[1].value == 0x401000);
    assert(bin->symtab_symbols[1].size == 64);

    // [2] my_var
    assert(strcmp(bin->symtab_symbols[2].name->data, "my_var") == 0);
    assert(N00B_ELF64_ST_TYPE(bin->symtab_symbols[2].info) == STT_OBJECT);
    assert(bin->symtab_symbols[2].value == 0x402000);
    assert(bin->symtab_symbols[2].size == 8);

    printf("  [PASS] symtab_parsing\n");
}

// ============================================================================
// Test: dynamic table parsing
// ============================================================================

static void
test_dynamic_parsing(void)
{
    n00b_buffer_t *buf = make_elf64_with_dynamic();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_elf_binary_t *bin = n00b_result_get(r);

    // Should have dynamic entries (DT_NEEDED, DT_STRTAB, DT_STRSZ,
    // DT_SYMTAB — DT_NULL is not stored).
    assert(bin->num_dynamic >= 4);

    // Check DT_NEEDED is present.
    bool found_needed = false;

    for (uint32_t i = 0; i < bin->num_dynamic; i++) {
        if (bin->dynamic_entries[i].tag == DT_NEEDED) {
            found_needed = true;
            assert(bin->dynamic_entries[i].value == 1);
            break;
        }
    }

    assert(found_needed);

    printf("  [PASS] dynamic_parsing\n");
}

// ============================================================================
// Test: note parsing
// ============================================================================

static void
test_note_parsing(void)
{
    n00b_buffer_t *buf = make_elf64_with_notes();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_elf_binary_t *bin = n00b_result_get(r);

    assert(bin->num_notes >= 1);

    // Check the note.
    assert(strcmp(bin->notes[0].name->data, "GNU") == 0);
    assert(bin->notes[0].type == NT_GNU_ABI_TAG);
    assert(bin->notes[0].desc != nullptr);

    printf("  [PASS] note_parsing\n");
}

// ============================================================================
// Test: relocation parsing
// ============================================================================

static void
test_relocation_parsing(void)
{
    n00b_buffer_t *buf = make_elf64_with_relocations();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_elf_binary_t *bin = n00b_result_get(r);

    assert(bin->num_relocations == 2);

    // [0] R_X86_64_64
    assert(bin->relocations[0].offset == 0x401000);
    assert(N00B_ELF64_R_TYPE(bin->relocations[0].info) == R_X86_64_64);
    assert(bin->relocations[0].has_addend);
    assert(bin->relocations[0].addend == 0);

    // [1] R_X86_64_PC32
    assert(bin->relocations[1].offset == 0x401008);
    assert(N00B_ELF64_R_TYPE(bin->relocations[1].info) == R_X86_64_PC32);
    assert(bin->relocations[1].has_addend);
    assert(bin->relocations[1].addend == -4);

    printf("  [PASS] relocation_parsing\n");
}

// ============================================================================
// Test: section_by_name query
// ============================================================================

static void
test_section_by_name(void)
{
    n00b_buffer_t *buf = make_elf64_with_symbols();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_elf_binary_t *bin = n00b_result_get(r);

    n00b_option_t(n00b_elf_section_t *) shstrtab_opt
        = n00b_elf_section_by_name(bin, ".shstrtab");
    assert(n00b_option_is_set(shstrtab_opt));
    assert(n00b_option_get(shstrtab_opt)->type == SHT_STRTAB);

    n00b_option_t(n00b_elf_section_t *) strtab_opt
        = n00b_elf_section_by_name(bin, ".strtab");
    assert(n00b_option_is_set(strtab_opt));
    assert(n00b_option_get(strtab_opt)->type == SHT_STRTAB);

    n00b_option_t(n00b_elf_section_t *) symtab_opt
        = n00b_elf_section_by_name(bin, ".symtab");
    assert(n00b_option_is_set(symtab_opt));
    assert(n00b_option_get(symtab_opt)->type == SHT_SYMTAB);

    printf("  [PASS] section_by_name\n");
}

// ============================================================================
// Test: section_by_type query
// ============================================================================

static void
test_section_by_type(void)
{
    n00b_buffer_t *buf = make_elf64_with_symbols();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_elf_binary_t *bin = n00b_result_get(r);

    // First SHT_STRTAB should be .shstrtab (section 1).
    n00b_option_t(n00b_elf_section_t *) strtab_opt
        = n00b_elf_section_by_type(bin, SHT_STRTAB);
    assert(n00b_option_is_set(strtab_opt));
    assert(strcmp(n00b_option_get(strtab_opt)->name->data, ".shstrtab") == 0);

    n00b_option_t(n00b_elf_section_t *) symtab_opt
        = n00b_elf_section_by_type(bin, SHT_SYMTAB);
    assert(n00b_option_is_set(symtab_opt));
    assert(strcmp(n00b_option_get(symtab_opt)->name->data, ".symtab") == 0);

    printf("  [PASS] section_by_type\n");
}

// ============================================================================
// Test: segment_by_type query
// ============================================================================

static void
test_segment_by_type(void)
{
    n00b_buffer_t *buf = make_elf64_with_dynamic();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_elf_binary_t *bin = n00b_result_get(r);

    assert(n00b_option_is_set(n00b_elf_segment_by_type(bin, PT_LOAD)));
    assert(n00b_option_is_set(n00b_elf_segment_by_type(bin, PT_DYNAMIC)));

    printf("  [PASS] segment_by_type\n");
}

// ============================================================================
// Test: symbol_by_name query
// ============================================================================

static void
test_symbol_by_name(void)
{
    n00b_buffer_t *buf = make_elf64_with_symbols();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_elf_binary_t *bin = n00b_result_get(r);

    n00b_option_t(n00b_elf_symbol_t *) func_opt
        = n00b_elf_symbol_by_name(bin, "my_func");
    assert(n00b_option_is_set(func_opt));
    assert(n00b_option_get(func_opt)->value == 0x401000);

    n00b_option_t(n00b_elf_symbol_t *) var_opt
        = n00b_elf_symbol_by_name(bin, "my_var");
    assert(n00b_option_is_set(var_opt));
    assert(n00b_option_get(var_opt)->value == 0x402000);

    // Also test specific symtab-only path.
    assert(n00b_option_is_set(n00b_elf_symtab_by_name(bin, "my_func")));

    printf("  [PASS] symbol_by_name\n");
}

// ============================================================================
// Test: dynamic_by_tag query
// ============================================================================

static void
test_dynamic_by_tag(void)
{
    n00b_buffer_t *buf = make_elf64_with_dynamic();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_elf_binary_t *bin = n00b_result_get(r);

    n00b_option_t(n00b_elf_dynamic_t *) needed_opt
        = n00b_elf_dynamic_by_tag(bin, DT_NEEDED);
    assert(n00b_option_is_set(needed_opt));
    assert(n00b_option_get(needed_opt)->value == 1);

    assert(n00b_option_is_set(n00b_elf_dynamic_by_tag(bin, DT_STRTAB)));

    printf("  [PASS] dynamic_by_tag\n");
}

// ============================================================================
// Test: not-found returns nullptr
// ============================================================================

static void
test_not_found_returns_null(void)
{
    n00b_buffer_t *buf = make_minimal_elf64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_elf_binary_t *bin = n00b_result_get(r);

    assert(!n00b_option_is_set(n00b_elf_section_by_name(bin, ".nonexistent")));
    assert(!n00b_option_is_set(n00b_elf_section_by_type(bin, SHT_SYMTAB)));
    assert(!n00b_option_is_set(n00b_elf_section_at_addr(bin, 0xDEADBEEF)));
    assert(!n00b_option_is_set(n00b_elf_segment_by_type(bin, PT_DYNAMIC)));
    assert(!n00b_option_is_set(n00b_elf_segment_at_addr(bin, 0xDEADBEEF)));
    assert(!n00b_option_is_set(n00b_elf_symbol_by_name(bin, "nosuch")));
    assert(!n00b_option_is_set(n00b_elf_symtab_by_name(bin, "nosuch")));
    assert(!n00b_option_is_set(n00b_elf_dynsym_by_name(bin, "nosuch")));
    assert(!n00b_option_is_set(n00b_elf_dynamic_by_tag(bin, DT_NEEDED)));
    assert(!n00b_option_is_set(n00b_elf_note_by_type(bin, NT_GNU_ABI_TAG)));

    // Predicate forms.
    assert(!n00b_elf_has_section(bin, ".nonexistent"));
    assert(n00b_elf_has_section(bin, ".shstrtab"));
    assert(n00b_elf_has_segment(bin, PT_LOAD));
    assert(!n00b_elf_has_segment(bin, PT_DYNAMIC));
    assert(!n00b_elf_has_interpreter(bin));

    // nullptr bin should be safe.
    assert(!n00b_option_is_set(n00b_elf_section_by_name(nullptr, ".text")));
    assert(!n00b_option_is_set(n00b_elf_symbol_by_name(nullptr, "foo")));
    assert(!n00b_elf_has_interpreter(nullptr));

    printf("  [PASS] not_found_returns_null\n");
}

// ============================================================================
// Test: core dump note parsing
// ============================================================================

/// Write an ELF64 header with a custom e_type.
static void
write_elf64_core_header(uint8_t *p,
                        uint16_t etype,
                        uint64_t phoff,
                        uint16_t phnum,
                        uint64_t shoff,
                        uint16_t shnum,
                        uint16_t shstrndx)
{
    p[0] = 0x7f; p[1] = 'E'; p[2] = 'L'; p[3] = 'F';
    p[EI_CLASS]   = ELFCLASS64;
    p[EI_DATA]    = ELFDATA2LSB;
    p[EI_VERSION] = EV_CURRENT;

    put16(p + 16, etype);
    put16(p + 18, EM_X86_64);
    put32(p + 20, EV_CURRENT);
    put64(p + 24, 0);             // e_entry
    put64(p + 32, phoff);
    put64(p + 40, shoff);
    put16(p + 52, 64);            // e_ehsize
    put16(p + 54, 56);            // e_phentsize
    put16(p + 56, phnum);
    put16(p + 58, 64);            // e_shentsize
    put16(p + 60, shnum);
    put16(p + 62, shstrndx);
}

/// Helper: write a single ELF note into buf at offset, return bytes written.
static size_t
write_note(uint8_t *p, const char *name, uint32_t type,
           const void *desc, uint32_t descsz)
{
    uint32_t namesz = (uint32_t)strlen(name) + 1;
    uint32_t name_aligned = (namesz + 3) & ~3u;
    uint32_t desc_aligned = (descsz + 3) & ~3u;

    put32(p + 0, namesz);
    put32(p + 4, descsz);
    put32(p + 8, type);
    memcpy(p + 12, name, namesz);

    if (desc && descsz > 0) {
        memcpy(p + 12 + name_aligned, desc, descsz);
    }

    return 12 + name_aligned + desc_aligned;
}

static void
test_core_notes(void)
{
    // Build a synthetic ELF core dump with:
    //   - NT_PRSTATUS (signal=11, pid=1234, ppid=1, pgrp=1234, sid=1234)
    //   - NT_PRPSINFO (state=0, fname="test_prog", psargs="./test_prog arg1")
    //   - NT_AUXV (AT_PAGESZ=4096, AT_NULL=0)
    //   - NT_FILE (one mapped file)

    // Build note descriptors.

    // NT_PRSTATUS (x86_64): 336 bytes total
    // Layout: si_signo(4) + si_code(4) + si_errno(4) + cursig(2) + pad(2)
    //         + sigpend(8) + sighold(8) + pid(4) + ppid(4) + pgrp(4) + sid(4)
    //         + utime(16) + stime(16) + cutime(16) + cstime(16)
    //         + registers (27 * 8 = 216 bytes) + 8 bytes padding
    //         Total: 336 bytes
    uint8_t prstatus_desc[336] = {0};
    int32_t sig = 11, pid = 1234, ppid = 1, pgrp = 1234, sid = 1234;
    memcpy(prstatus_desc + 0, &sig, 4);      // si_signo
    memcpy(prstatus_desc + 24, &pid, 4);     // pid
    memcpy(prstatus_desc + 28, &ppid, 4);    // ppid
    memcpy(prstatus_desc + 32, &pgrp, 4);    // pgrp
    memcpy(prstatus_desc + 36, &sid, 4);     // sid
    // Registers at offset 112 — just set a known value at start.
    uint64_t rax_val = 0xDEADBEEF;
    memcpy(prstatus_desc + 112, &rax_val, 8);

    // NT_PRPSINFO (x86_64): 136 bytes
    uint8_t prpsinfo_desc[136] = {0};
    prpsinfo_desc[0] = 0;       // state
    prpsinfo_desc[1] = 'S';     // sname
    prpsinfo_desc[2] = 0;       // zombie
    prpsinfo_desc[3] = 0;       // nice
    int32_t ps_uid = 1000, ps_gid = 1000;
    int32_t ps_pid = 1234, ps_ppid = 1, ps_pgrp = 1234, ps_sid = 1234;
    memcpy(prpsinfo_desc + 12, &ps_uid, 4);
    memcpy(prpsinfo_desc + 16, &ps_gid, 4);
    memcpy(prpsinfo_desc + 20, &ps_pid, 4);
    memcpy(prpsinfo_desc + 24, &ps_ppid, 4);
    memcpy(prpsinfo_desc + 28, &ps_pgrp, 4);
    memcpy(prpsinfo_desc + 32, &ps_sid, 4);
    memcpy(prpsinfo_desc + 40, "test_prog", 9);
    memcpy(prpsinfo_desc + 56, "./test_prog arg1", 16);

    // NT_AUXV: 2 entries (AT_PAGESZ=6, value=4096) + (AT_NULL=0, value=0)
    uint8_t auxv_desc[32] = {0};
    uint64_t at_pagesz = 6, pgsz_val = 4096;
    uint64_t at_null = 0, null_val = 0;
    memcpy(auxv_desc + 0,  &at_pagesz, 8);
    memcpy(auxv_desc + 8,  &pgsz_val, 8);
    memcpy(auxv_desc + 16, &at_null, 8);
    memcpy(auxv_desc + 24, &null_val, 8);

    // NT_FILE: count=1, page_size=4096,
    //   entry: start=0x400000, end=0x401000, offset=0
    //   filename: "/usr/bin/test\0"
    const char *filename = "/usr/bin/test";
    size_t fname_len = strlen(filename) + 1;  // 14
    size_t file_desc_size = 16 + 24 + fname_len;  // 54
    uint8_t file_desc[64] = {0};
    uint64_t fcount = 1, fpgsz = 4096;
    uint64_t fstart = 0x400000, fend = 0x401000, foff = 0;
    memcpy(file_desc + 0, &fcount, 8);
    memcpy(file_desc + 8, &fpgsz, 8);
    memcpy(file_desc + 16, &fstart, 8);
    memcpy(file_desc + 24, &fend, 8);
    memcpy(file_desc + 32, &foff, 8);
    memcpy(file_desc + 40, filename, fname_len);

    // Calculate note section layout.
    // Each note: 12 (header) + aligned_name + aligned_desc
    size_t note1 = 12 + 8 + ((sizeof(prstatus_desc) + 3) & ~3u);   // CORE\0 = 5, aligned 8
    size_t note2 = 12 + 8 + ((sizeof(prpsinfo_desc) + 3) & ~3u);
    size_t note3 = 12 + 8 + ((sizeof(auxv_desc) + 3) & ~3u);
    size_t note4 = 12 + 8 + ((file_desc_size + 3) & ~3u);
    size_t notes_total = note1 + note2 + note3 + note4;

    // Layout:
    //   [0..63]           ELF header (ET_CORE)
    //   [64..119]         PT_NOTE phdr
    //   [120..183]        Section headers: [0] SHT_NULL, [1] .note
    //   Note: we skip .shstrtab since it's optional for parsing
    //   [256..]           Note content
    size_t note_content_off = 256;
    size_t total_size = note_content_off + notes_total + 64;

    n00b_buffer_t *buf = n00b_buffer_new(total_size);
    memset(buf->data, 0, total_size);
    buf->byte_len = total_size;
    uint8_t *p = (uint8_t *)buf->data;

    // ELF header: ET_CORE, 1 phdr, 2 section headers
    write_elf64_core_header(p, ET_CORE, 64, 1, 120, 2, 0);

    // PT_NOTE phdr
    write_phdr(p + 64, PT_NOTE, PF_R,
               note_content_off, 0x400000 + note_content_off,
               notes_total, notes_total, 4);

    // Section header [0] = SHT_NULL (already zero)
    // Section header [1] = SHT_NOTE
    write_shdr(p + 120 + 64,
               0, SHT_NOTE, 0, 0x400000 + note_content_off,
               note_content_off, notes_total,
               0, 0, 4, 0);

    // Write notes
    uint8_t *np = p + note_content_off;
    size_t off = 0;

    off += write_note(np + off, "CORE", NT_PRSTATUS,
                      prstatus_desc, sizeof(prstatus_desc));
    off += write_note(np + off, "CORE", NT_PRPSINFO,
                      prpsinfo_desc, sizeof(prpsinfo_desc));
    off += write_note(np + off, "CORE", NT_AUXV,
                      auxv_desc, sizeof(auxv_desc));
    off += write_note(np + off, "LINUX", NT_FILE,
                      file_desc, (uint32_t)file_desc_size);

    // Parse
    n00b_bstream_t *s = n00b_bstream_new(buf);
    auto r = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_elf_binary_t *bin = n00b_result_get(r);

    // Basic checks.
    assert(n00b_elf_is_core(bin));
    assert(bin->header.type == ET_CORE);
    assert(bin->num_notes == 4);

    // Core info should be parsed.
    n00b_option_t(n00b_elf_core_info_t *) ci_opt = n00b_elf_core_info(bin);
    assert(n00b_option_is_set(ci_opt));
    n00b_elf_core_info_t *ci = n00b_option_get(ci_opt);

    // Verify prstatus.
    assert(ci->num_prstatus == 1);
    assert(ci->prstatus[0].signal == 11);
    assert(ci->prstatus[0].pid == 1234);
    assert(ci->prstatus[0].ppid == 1);
    assert(ci->prstatus[0].pgrp == 1234);
    assert(ci->prstatus[0].sid == 1234);
    assert(ci->prstatus[0].registers != nullptr);

    // Check register data.
    uint64_t reg0;
    memcpy(&reg0, ci->prstatus[0].registers->data, 8);
    assert(reg0 == 0xDEADBEEF);

    // Verify prpsinfo.
    assert(ci->prpsinfo != nullptr);
    assert(ci->prpsinfo->sname == 'S');
    assert(ci->prpsinfo->pid == 1234);
    assert(ci->prpsinfo->uid == 1000);
    assert(ci->prpsinfo->gid == 1000);
    assert(strcmp(ci->prpsinfo->fname, "test_prog") == 0);
    assert(strstr(ci->prpsinfo->psargs, "test_prog") != nullptr);

    // Verify auxv.
    assert(ci->num_auxv == 1);  // AT_NULL terminates, not included.
    assert(ci->auxv[0].type == 6);   // AT_PAGESZ
    assert(ci->auxv[0].value == 4096);

    // Verify file mappings.
    assert(ci->num_files == 1);
    assert(ci->files[0].start == 0x400000);
    assert(ci->files[0].end == 0x401000);
    assert(ci->files[0].name != nullptr);
    assert(strcmp(ci->files[0].name->data, "/usr/bin/test") == 0);

    // Non-core binary should not have core_info.
    assert(!n00b_elf_is_core(nullptr));

    printf("  [PASS] core_notes\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running ELF parser tests...\n");

    test_parse_synthetic_elf64();
    test_parse_bad_magic();
    test_parse_elf32_rejected();
    test_parse_truncated();
    test_parse_real_binary();
    test_null_stream();
    test_symtab_parsing();
    test_dynamic_parsing();
    test_note_parsing();
    test_relocation_parsing();
    test_section_by_name();
    test_section_by_type();
    test_segment_by_type();
    test_symbol_by_name();
    test_dynamic_by_tag();
    test_not_found_returns_null();
    test_core_notes();

    printf("All ELF parser tests passed.\n");
    n00b_shutdown();
    return 0;
}

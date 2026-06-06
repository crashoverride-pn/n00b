#include <string.h>
#include "compiler/objfile/elf.h"
#include "compiler/objfile/demangle.h"

// ============================================================================
// Internal helpers
// ============================================================================

/// Read a NUL-terminated string from a string table section's content buffer.
static n00b_string_t *
strtab_get(n00b_buffer_t *strtab, uint32_t offset)
{
    if (!strtab || offset >= (uint32_t)n00b_buffer_len(strtab)) {
        return n00b_string_empty();
    }

    const char *base = strtab->data + offset;
    size_t      max  = n00b_buffer_len(strtab) - offset;
    size_t      len  = strnlen(base, max);

    return n00b_string_from_raw(base, (int64_t)len);
}

/// Read a NUL-terminated string from a dynstr region within the stream.
static n00b_string_t *
dynstr_get(n00b_bstream_t *stream, uint64_t strtab_offset, uint64_t strtab_size,
           uint32_t name_offset)
{
    if (name_offset >= strtab_size) {
        return n00b_string_empty();
    }

    size_t saved = n00b_bstream_pos(stream);
    auto   r     = n00b_bstream_setpos(stream, strtab_offset + name_offset);

    if (n00b_result_is_err(r)) {
        return n00b_string_empty();
    }

    auto sr = n00b_bstream_read_cstring(stream);

    n00b_bstream_setpos(stream, saved);

    if (n00b_result_is_err(sr)) {
        return n00b_string_empty();
    }

    return n00b_result_get(sr);
}

/// Map ELF e_machine + EI_CLASS to n00b_arch_t.
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

/// Find the value of a dynamic tag. Returns 0 if not found.
static uint64_t
find_dynamic_val(n00b_elf_binary_t *bin, int64_t tag)
{
    for (uint32_t i = 0; i < bin->num_dynamic; i++) {
        if (bin->dynamic_entries[i].tag == tag) {
            return bin->dynamic_entries[i].value;
        }
    }
    return 0;
}

/// Find the file offset for a virtual address using segments.
static bool
vaddr_to_offset(n00b_elf_binary_t *bin, uint64_t vaddr, uint64_t *out_offset)
{
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_elf_segment_t *seg = &bin->segments[i];

        if (seg->type == PT_LOAD
            && vaddr >= seg->vaddr
            && vaddr < seg->vaddr + seg->memsz) {
            *out_offset = seg->offset + (vaddr - seg->vaddr);
            return true;
        }
    }
    return false;
}

// ============================================================================
// parse_header
// ============================================================================

static n00b_result_t(bool)
parse_header(n00b_bstream_t *stream, n00b_elf_binary_t *bin)
{
    n00b_bstream_setpos(stream, 0);

    if (!n00b_bstream_can_read(stream, sizeof(n00b_elf64_ehdr_t))) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }

    // Read e_ident manually first to validate and set endianness.
    auto ident_r = n00b_bstream_read_bytes(stream, EI_NIDENT);

    if (n00b_result_is_err(ident_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }

    n00b_buffer_t *ident_buf = n00b_result_get(ident_r);
    const uint8_t *ident     = (const uint8_t *)ident_buf->data;

    // Validate magic.
    if (ident[EI_MAG0] != 0x7f || ident[EI_MAG1] != 'E'
        || ident[EI_MAG2] != 'L' || ident[EI_MAG3] != 'F') {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }

    // Must be 64-bit.
    if (ident[EI_CLASS] != ELFCLASS64) {
        return n00b_result_err(bool, N00B_ERR_NOT_SUPPORTED);
    }

    // Set endianness from EI_DATA.
    if (ident[EI_DATA] == ELFDATA2LSB) {
        n00b_bstream_set_endian(stream, N00B_ENDIAN_LITTLE);
    }
    else if (ident[EI_DATA] == ELFDATA2MSB) {
        n00b_bstream_set_endian(stream, N00B_ENDIAN_BIG);
    }
    else {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }

    memcpy(bin->header.ident, ident, EI_NIDENT);

    // Read remaining header fields using endian-aware stream reads.
    auto type_r = n00b_bstream_read_u16(stream);

    if (n00b_result_is_err(type_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }
    bin->header.type = n00b_result_get(type_r);

    auto machine_r = n00b_bstream_read_u16(stream);

    if (n00b_result_is_err(machine_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }
    bin->header.machine = n00b_result_get(machine_r);

    auto version_r = n00b_bstream_read_u32(stream);

    if (n00b_result_is_err(version_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }
    bin->header.version = n00b_result_get(version_r);

    auto entry_r = n00b_bstream_read_u64(stream);

    if (n00b_result_is_err(entry_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }
    bin->header.entry = n00b_result_get(entry_r);

    auto phoff_r = n00b_bstream_read_u64(stream);

    if (n00b_result_is_err(phoff_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }
    bin->header.phoff = n00b_result_get(phoff_r);

    auto shoff_r = n00b_bstream_read_u64(stream);

    if (n00b_result_is_err(shoff_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }
    bin->header.shoff = n00b_result_get(shoff_r);

    auto flags_r = n00b_bstream_read_u32(stream);

    if (n00b_result_is_err(flags_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }
    bin->header.flags = n00b_result_get(flags_r);

    auto ehsize_r = n00b_bstream_read_u16(stream);

    if (n00b_result_is_err(ehsize_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }
    bin->header.ehsize = n00b_result_get(ehsize_r);

    auto phentsize_r = n00b_bstream_read_u16(stream);

    if (n00b_result_is_err(phentsize_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }
    bin->header.phentsize = n00b_result_get(phentsize_r);

    auto phnum_r = n00b_bstream_read_u16(stream);

    if (n00b_result_is_err(phnum_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }
    bin->header.phnum = n00b_result_get(phnum_r);

    auto shentsize_r = n00b_bstream_read_u16(stream);

    if (n00b_result_is_err(shentsize_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }
    bin->header.shentsize = n00b_result_get(shentsize_r);

    auto shnum_r = n00b_bstream_read_u16(stream);

    if (n00b_result_is_err(shnum_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }
    bin->header.shnum = n00b_result_get(shnum_r);

    auto shstrndx_r = n00b_bstream_read_u16(stream);

    if (n00b_result_is_err(shstrndx_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }
    bin->header.shstrndx = n00b_result_get(shstrndx_r);

    return n00b_result_ok(bool, true);
}

// ============================================================================
// parse_sections
// ============================================================================

static void
parse_sections(n00b_bstream_t *stream, n00b_elf_binary_t *bin)
{
    uint16_t shnum = bin->header.shnum;

    if (shnum == 0 || bin->header.shoff == 0) {
        return;
    }

    // Validate shentsize: must be at least 64 bytes for ELF64.
    if (bin->header.shentsize < 64) {
        return;
    }

    bin->sections     = n00b_alloc_array(n00b_elf_section_t, shnum);
    bin->num_sections = shnum;

    // First pass: read raw section headers.
    for (uint16_t i = 0; i < shnum; i++) {
        size_t off = bin->header.shoff
                   + (size_t)i * bin->header.shentsize;

        n00b_bstream_setpos(stream, off);

        n00b_elf_section_t *sec = &bin->sections[i];

        auto name_r = n00b_bstream_read_u32(stream);
        if (n00b_result_is_ok(name_r)) {
            // Store raw name index temporarily; resolve after shstrtab loaded.
            sec->info = n00b_result_get(name_r); // reuse info temporarily
        }

        auto type_r = n00b_bstream_read_u32(stream);
        if (n00b_result_is_ok(type_r))  sec->type = n00b_result_get(type_r);

        auto flags_r = n00b_bstream_read_u64(stream);
        if (n00b_result_is_ok(flags_r)) sec->flags = n00b_result_get(flags_r);

        auto addr_r = n00b_bstream_read_u64(stream);
        if (n00b_result_is_ok(addr_r))  sec->addr = n00b_result_get(addr_r);

        auto offset_r = n00b_bstream_read_u64(stream);
        if (n00b_result_is_ok(offset_r)) sec->offset = n00b_result_get(offset_r);

        auto size_r = n00b_bstream_read_u64(stream);
        if (n00b_result_is_ok(size_r))  sec->size = n00b_result_get(size_r);

        auto link_r = n00b_bstream_read_u32(stream);
        if (n00b_result_is_ok(link_r))  sec->link = n00b_result_get(link_r);

        // Now read the real sh_info (we temporarily stored sh_name in sec->info).
        uint32_t raw_name_idx = sec->info;
        auto info_r = n00b_bstream_read_u32(stream);
        if (n00b_result_is_ok(info_r))  sec->info = n00b_result_get(info_r);

        auto align_r = n00b_bstream_read_u64(stream);
        if (n00b_result_is_ok(align_r)) sec->addralign = n00b_result_get(align_r);

        auto entsize_r = n00b_bstream_read_u64(stream);
        if (n00b_result_is_ok(entsize_r)) sec->entsize = n00b_result_get(entsize_r);

        // Store raw name index in a separate temporary location.
        // We'll use the addralign to stash name indices is too hacky; instead
        // let's save name indices in a small array and resolve in second pass.
        // Actually, let's just store it in the name field as empty for now
        // and use a parallel array approach.
        // Simpler: temporarily reuse the name as empty, store raw_name_idx
        // into a local array below.
        (void)raw_name_idx;
    }

    // Load raw name indices again for name resolution.
    uint32_t *name_indices = n00b_alloc_array(uint32_t, shnum);

    for (uint16_t i = 0; i < shnum; i++) {
        size_t off = bin->header.shoff
                   + (size_t)i * bin->header.shentsize;

        n00b_bstream_setpos(stream, off);

        auto r = n00b_bstream_read_u32(stream);

        if (n00b_result_is_ok(r)) {
            name_indices[i] = n00b_result_get(r);
        }
    }

    // Load section content (except NOBITS).
    for (uint16_t i = 0; i < shnum; i++) {
        n00b_elf_section_t *sec = &bin->sections[i];

        if (sec->type != SHT_NOBITS && sec->size > 0 && sec->offset > 0) {
            auto cr = n00b_bstream_peek_bytes(stream, sec->offset, sec->size);

            if (n00b_result_is_ok(cr)) {
                sec->content = n00b_result_get(cr);
            }
        }
    }

    // Resolve names from shstrtab.
    uint16_t shstrndx = bin->header.shstrndx;

    if (shstrndx < shnum) {
        n00b_buffer_t *shstrtab = bin->sections[shstrndx].content;

        for (uint16_t i = 0; i < shnum; i++) {
            bin->sections[i].name = strtab_get(shstrtab, name_indices[i]);
        }
    }
}

// ============================================================================
// parse_segments
// ============================================================================

static void
parse_segments(n00b_bstream_t *stream, n00b_elf_binary_t *bin)
{
    uint16_t phnum = bin->header.phnum;

    if (phnum == 0 || bin->header.phoff == 0) {
        return;
    }

    // Validate phentsize: must be at least 56 bytes for ELF64.
    if (bin->header.phentsize < 56) {
        return;
    }

    bin->segments     = n00b_alloc_array(n00b_elf_segment_t, phnum);
    bin->num_segments = phnum;

    for (uint16_t i = 0; i < phnum; i++) {
        size_t off = bin->header.phoff
                   + (size_t)i * bin->header.phentsize;

        n00b_bstream_setpos(stream, off);

        n00b_elf_segment_t *seg = &bin->segments[i];

        auto type_r = n00b_bstream_read_u32(stream);
        if (n00b_result_is_ok(type_r)) seg->type = n00b_result_get(type_r);

        auto flags_r = n00b_bstream_read_u32(stream);
        if (n00b_result_is_ok(flags_r)) seg->flags = n00b_result_get(flags_r);

        auto offset_r = n00b_bstream_read_u64(stream);
        if (n00b_result_is_ok(offset_r)) seg->offset = n00b_result_get(offset_r);

        auto vaddr_r = n00b_bstream_read_u64(stream);
        if (n00b_result_is_ok(vaddr_r)) seg->vaddr = n00b_result_get(vaddr_r);

        auto paddr_r = n00b_bstream_read_u64(stream);
        if (n00b_result_is_ok(paddr_r)) seg->paddr = n00b_result_get(paddr_r);

        auto filesz_r = n00b_bstream_read_u64(stream);
        if (n00b_result_is_ok(filesz_r)) seg->filesz = n00b_result_get(filesz_r);

        auto memsz_r = n00b_bstream_read_u64(stream);
        if (n00b_result_is_ok(memsz_r)) seg->memsz = n00b_result_get(memsz_r);

        auto align_r = n00b_bstream_read_u64(stream);
        if (n00b_result_is_ok(align_r)) seg->align = n00b_result_get(align_r);

        // Read segment content.
        if (seg->filesz > 0) {
            auto cr = n00b_bstream_peek_bytes(stream, seg->offset, seg->filesz);

            if (n00b_result_is_ok(cr)) {
                seg->content = n00b_result_get(cr);
            }
        }

        // Extract interpreter string from PT_INTERP.
        if (seg->type == PT_INTERP && seg->content) {
            const char *interp = seg->content->data;
            size_t      len    = strnlen(interp, n00b_buffer_len(seg->content));

            bin->interpreter = n00b_string_from_raw(interp, (int64_t)len);
        }
    }
}

// ============================================================================
// parse_dynamic_table
// ============================================================================

static void
parse_dynamic_table(n00b_bstream_t *stream, n00b_elf_binary_t *bin)
{
    // Find PT_DYNAMIC segment.
    n00b_elf_segment_t *dyn_seg = nullptr;

    for (uint32_t i = 0; i < bin->num_segments; i++) {
        if (bin->segments[i].type == PT_DYNAMIC) {
            dyn_seg = &bin->segments[i];
            break;
        }
    }

    if (!dyn_seg || dyn_seg->filesz == 0) {
        return;
    }

    // Count entries (each is 16 bytes: d_tag + d_un).
    uint32_t max_entries = (uint32_t)(dyn_seg->filesz / 16);

    // First pass: count until DT_NULL.
    uint32_t count = 0;

    n00b_bstream_setpos(stream, dyn_seg->offset);

    for (uint32_t i = 0; i < max_entries; i++) {
        auto tag_r = n00b_bstream_read_i64(stream);

        if (n00b_result_is_err(tag_r)) {
            break;
        }

        int64_t tag = n00b_result_get(tag_r);

        n00b_bstream_advance(stream, 8); // skip d_val/d_ptr

        count++;

        if (tag == DT_NULL) {
            break;
        }
    }

    if (count == 0) {
        return;
    }

    bin->dynamic_entries = n00b_alloc_array(n00b_elf_dynamic_t, count);
    bin->num_dynamic     = count;

    // Second pass: read entries.
    n00b_bstream_setpos(stream, dyn_seg->offset);

    for (uint32_t i = 0; i < count; i++) {
        auto tag_r = n00b_bstream_read_i64(stream);
        auto val_r = n00b_bstream_read_u64(stream);

        if (n00b_result_is_ok(tag_r)) {
            bin->dynamic_entries[i].tag = n00b_result_get(tag_r);
        }

        if (n00b_result_is_ok(val_r)) {
            bin->dynamic_entries[i].value = n00b_result_get(val_r);
        }
    }
}

// ============================================================================
// parse_symtab — .symtab section symbols
// ============================================================================

static void
parse_symtab(n00b_bstream_t *stream, n00b_elf_binary_t *bin)
{
    // Find SHT_SYMTAB section.
    n00b_elf_section_t *symtab_sec = nullptr;

    for (uint32_t i = 0; i < bin->num_sections; i++) {
        if (bin->sections[i].type == SHT_SYMTAB) {
            symtab_sec = &bin->sections[i];
            break;
        }
    }

    if (!symtab_sec || symtab_sec->size == 0 || symtab_sec->entsize == 0) {
        return;
    }

    uint32_t nsyms = (uint32_t)(symtab_sec->size / symtab_sec->entsize);

    // Get linked string table.
    n00b_buffer_t *strtab = nullptr;

    if (symtab_sec->link < bin->num_sections) {
        strtab = bin->sections[symtab_sec->link].content;
    }

    bin->symtab_symbols = n00b_alloc_array(n00b_elf_symbol_t, nsyms);
    bin->num_symtab     = nsyms;

    n00b_bstream_setpos(stream, symtab_sec->offset);

    for (uint32_t i = 0; i < nsyms; i++) {
        n00b_elf_symbol_t *sym = &bin->symtab_symbols[i];

        auto name_r  = n00b_bstream_read_u32(stream);
        auto info_r  = n00b_bstream_read_u8(stream);
        auto other_r = n00b_bstream_read_u8(stream);
        auto shndx_r = n00b_bstream_read_u16(stream);
        auto value_r = n00b_bstream_read_u64(stream);
        auto size_r  = n00b_bstream_read_u64(stream);

        if (n00b_result_is_ok(info_r))  sym->info  = n00b_result_get(info_r);
        if (n00b_result_is_ok(other_r)) sym->other = n00b_result_get(other_r);
        if (n00b_result_is_ok(shndx_r)) sym->shndx = n00b_result_get(shndx_r);
        if (n00b_result_is_ok(value_r)) sym->value = n00b_result_get(value_r);
        if (n00b_result_is_ok(size_r))  sym->size  = n00b_result_get(size_r);

        if (n00b_result_is_ok(name_r) && strtab) {
            sym->name = strtab_get(strtab, n00b_result_get(name_r));
        }
    }
}

// ============================================================================
// parse_dynsym — .dynsym section symbols
// ============================================================================

static void
parse_dynsym(n00b_bstream_t *stream, n00b_elf_binary_t *bin)
{
    // Use DT_SYMTAB, DT_STRTAB, DT_STRSZ from dynamic table.
    uint64_t symtab_vaddr = find_dynamic_val(bin, DT_SYMTAB);
    uint64_t strtab_vaddr = find_dynamic_val(bin, DT_STRTAB);
    uint64_t strsz        = find_dynamic_val(bin, DT_STRSZ);

    if (symtab_vaddr == 0) {
        return;
    }

    uint64_t symtab_offset = 0;
    uint64_t strtab_offset = 0;

    if (!vaddr_to_offset(bin, symtab_vaddr, &symtab_offset)) {
        return;
    }

    if (strtab_vaddr != 0) {
        vaddr_to_offset(bin, strtab_vaddr, &strtab_offset);
    }

    // Determine symbol count.
    // Try GNU hash first, then SYSV hash, then fall back to section.
    uint32_t nsyms = 0;

    uint64_t gnu_hash_vaddr = find_dynamic_val(bin, DT_GNU_HASH);

    if (gnu_hash_vaddr != 0) {
        uint64_t gnu_hash_off = 0;

        if (vaddr_to_offset(bin, gnu_hash_vaddr, &gnu_hash_off)) {
            n00b_bstream_setpos(stream, gnu_hash_off);

            auto nbuckets_r  = n00b_bstream_read_u32(stream);
            auto symoffset_r = n00b_bstream_read_u32(stream);
            auto bloom_size_r = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(nbuckets_r)
                && n00b_result_is_ok(symoffset_r)
                && n00b_result_is_ok(bloom_size_r)) {
                uint32_t nbuckets  = n00b_result_get(nbuckets_r);
                uint32_t symoffset = n00b_result_get(symoffset_r);
                uint32_t bloom_sz  = n00b_result_get(bloom_size_r);

                // Skip bloom_shift + bloom filter + buckets.
                n00b_bstream_advance(stream, 4); // bloom_shift
                n00b_bstream_advance(stream, (size_t)bloom_sz * 8);

                // Find max bucket value.
                uint32_t max_bucket = 0;

                for (uint32_t i = 0; i < nbuckets; i++) {
                    auto br = n00b_bstream_read_u32(stream);

                    if (n00b_result_is_ok(br)) {
                        uint32_t bval = n00b_result_get(br);
                        if (bval > max_bucket) {
                            max_bucket = bval;
                        }
                    }
                }

                if (max_bucket >= symoffset) {
                    // Walk chain from max_bucket to find last symbol.
                    // Chain starts right after buckets in the stream.
                    size_t chains_base = n00b_bstream_pos(stream);
                    uint32_t chain_idx = max_bucket - symoffset;

                    n00b_bstream_setpos(stream,
                                       chains_base + (size_t)chain_idx * 4);

                    while (true) {
                        auto cr = n00b_bstream_read_u32(stream);

                        if (n00b_result_is_err(cr)) {
                            break;
                        }

                        uint32_t chain_val = n00b_result_get(cr);
                        max_bucket++;

                        if (chain_val & 1) {
                            break;
                        }
                    }

                    nsyms = max_bucket;
                }
            }
        }
    }

    if (nsyms == 0) {
        uint64_t hash_vaddr = find_dynamic_val(bin, DT_HASH);

        if (hash_vaddr != 0) {
            uint64_t hash_off = 0;

            if (vaddr_to_offset(bin, hash_vaddr, &hash_off)) {
                n00b_bstream_setpos(stream, hash_off);

                n00b_bstream_advance(stream, 4); // nbucket

                auto nchain_r = n00b_bstream_read_u32(stream);

                if (n00b_result_is_ok(nchain_r)) {
                    nsyms = n00b_result_get(nchain_r);
                }
            }
        }
    }

    // Fallback: try SHT_DYNSYM section.
    if (nsyms == 0) {
        for (uint32_t i = 0; i < bin->num_sections; i++) {
            if (bin->sections[i].type == SHT_DYNSYM
                && bin->sections[i].entsize > 0) {
                nsyms = (uint32_t)(bin->sections[i].size
                                   / bin->sections[i].entsize);
                break;
            }
        }
    }

    if (nsyms == 0) {
        return;
    }

    bin->dynsym_symbols = n00b_alloc_array(n00b_elf_symbol_t, nsyms);
    bin->num_dynsym     = nsyms;

    n00b_bstream_setpos(stream, symtab_offset);

    for (uint32_t i = 0; i < nsyms; i++) {
        n00b_elf_symbol_t *sym = &bin->dynsym_symbols[i];

        auto name_r  = n00b_bstream_read_u32(stream);
        auto info_r  = n00b_bstream_read_u8(stream);
        auto other_r = n00b_bstream_read_u8(stream);
        auto shndx_r = n00b_bstream_read_u16(stream);
        auto value_r = n00b_bstream_read_u64(stream);
        auto size_r  = n00b_bstream_read_u64(stream);

        if (n00b_result_is_ok(info_r))  sym->info  = n00b_result_get(info_r);
        if (n00b_result_is_ok(other_r)) sym->other = n00b_result_get(other_r);
        if (n00b_result_is_ok(shndx_r)) sym->shndx = n00b_result_get(shndx_r);
        if (n00b_result_is_ok(value_r)) sym->value = n00b_result_get(value_r);
        if (n00b_result_is_ok(size_r))  sym->size  = n00b_result_get(size_r);

        if (n00b_result_is_ok(name_r) && strtab_offset != 0 && strsz != 0) {
            sym->name = dynstr_get(stream, strtab_offset, strsz,
                                   n00b_result_get(name_r));
        }
    }
}

// ============================================================================
// parse_relocations
// ============================================================================

static void
parse_relocations(n00b_bstream_t *stream, n00b_elf_binary_t *bin)
{
    // Count total relocations from REL and RELA sections.
    uint32_t total = 0;

    for (uint32_t i = 0; i < bin->num_sections; i++) {
        n00b_elf_section_t *sec = &bin->sections[i];

        if ((sec->type == SHT_REL || sec->type == SHT_RELA)
            && sec->entsize > 0 && sec->size > 0) {
            total += (uint32_t)(sec->size / sec->entsize);
        }
    }

    if (total == 0) {
        return;
    }

    bin->relocations     = n00b_alloc_array(n00b_elf_relocation_t, total);
    bin->num_relocations = 0;

    for (uint32_t i = 0; i < bin->num_sections; i++) {
        n00b_elf_section_t *sec = &bin->sections[i];

        if (sec->type != SHT_REL && sec->type != SHT_RELA) {
            continue;
        }

        if (sec->entsize == 0 || sec->size == 0) {
            continue;
        }

        bool     is_rela = (sec->type == SHT_RELA);
        uint32_t nrels   = (uint32_t)(sec->size / sec->entsize);

        n00b_bstream_setpos(stream, sec->offset);

        for (uint32_t j = 0; j < nrels; j++) {
            if (bin->num_relocations >= total) {
                break;
            }

            n00b_elf_relocation_t *rel = &bin->relocations[bin->num_relocations];

            auto offset_r = n00b_bstream_read_u64(stream);
            auto info_r   = n00b_bstream_read_u64(stream);

            if (n00b_result_is_ok(offset_r)) {
                rel->offset = n00b_result_get(offset_r);
            }

            if (n00b_result_is_ok(info_r)) {
                rel->info = n00b_result_get(info_r);
            }

            if (is_rela) {
                auto addend_r = n00b_bstream_read_i64(stream);

                if (n00b_result_is_ok(addend_r)) {
                    rel->addend = n00b_result_get(addend_r);
                }

                rel->has_addend = true;
            }
            else {
                rel->addend     = 0;
                rel->has_addend = false;
            }

            bin->num_relocations++;
        }
    }
}

// ============================================================================
// parse_gnu_hash
// ============================================================================

static void
parse_gnu_hash(n00b_bstream_t *stream, n00b_elf_binary_t *bin)
{
    uint64_t gnu_hash_vaddr = find_dynamic_val(bin, DT_GNU_HASH);

    if (gnu_hash_vaddr == 0) {
        return;
    }

    uint64_t offset = 0;

    if (!vaddr_to_offset(bin, gnu_hash_vaddr, &offset)) {
        return;
    }

    n00b_bstream_setpos(stream, offset);

    auto nbuckets_r   = n00b_bstream_read_u32(stream);
    auto symoffset_r  = n00b_bstream_read_u32(stream);
    auto bloom_size_r = n00b_bstream_read_u32(stream);
    auto bloom_shift_r = n00b_bstream_read_u32(stream);

    if (n00b_result_is_err(nbuckets_r) || n00b_result_is_err(symoffset_r)
        || n00b_result_is_err(bloom_size_r) || n00b_result_is_err(bloom_shift_r)) {
        return;
    }

    n00b_elf_gnu_hash_t *gh = n00b_alloc(n00b_elf_gnu_hash_t);

    gh->nbuckets    = n00b_result_get(nbuckets_r);
    gh->symoffset   = n00b_result_get(symoffset_r);
    gh->bloom_size  = n00b_result_get(bloom_size_r);
    gh->bloom_shift = n00b_result_get(bloom_shift_r);

    // Read bloom filter.
    if (gh->bloom_size > 0) {
        gh->bloom = n00b_alloc_array(uint64_t, gh->bloom_size);

        for (uint32_t i = 0; i < gh->bloom_size; i++) {
            auto r = n00b_bstream_read_u64(stream);

            if (n00b_result_is_ok(r)) {
                gh->bloom[i] = n00b_result_get(r);
            }
        }
    }

    // Read buckets.
    if (gh->nbuckets > 0) {
        gh->buckets = n00b_alloc_array(uint32_t, gh->nbuckets);

        for (uint32_t i = 0; i < gh->nbuckets; i++) {
            auto r = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(r)) {
                gh->buckets[i] = n00b_result_get(r);
            }
        }
    }

    // Read chains.
    // Chain count = total dynsyms - symoffset.
    if (bin->num_dynsym > gh->symoffset) {
        gh->nchains = bin->num_dynsym - gh->symoffset;
        gh->chains  = n00b_alloc_array(uint32_t, gh->nchains);

        for (uint32_t i = 0; i < gh->nchains; i++) {
            auto r = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(r)) {
                gh->chains[i] = n00b_result_get(r);
            }
        }
    }

    bin->gnu_hash = gh;
}

// ============================================================================
// parse_sysv_hash
// ============================================================================

static void
parse_sysv_hash(n00b_bstream_t *stream, n00b_elf_binary_t *bin)
{
    uint64_t hash_vaddr = find_dynamic_val(bin, DT_HASH);

    if (hash_vaddr == 0) {
        return;
    }

    uint64_t offset = 0;

    if (!vaddr_to_offset(bin, hash_vaddr, &offset)) {
        return;
    }

    n00b_bstream_setpos(stream, offset);

    auto nbucket_r = n00b_bstream_read_u32(stream);
    auto nchain_r  = n00b_bstream_read_u32(stream);

    if (n00b_result_is_err(nbucket_r) || n00b_result_is_err(nchain_r)) {
        return;
    }

    n00b_elf_sysv_hash_t *sh = n00b_alloc(n00b_elf_sysv_hash_t);

    sh->nbucket = n00b_result_get(nbucket_r);
    sh->nchain  = n00b_result_get(nchain_r);

    if (sh->nbucket > 0) {
        sh->buckets = n00b_alloc_array(uint32_t, sh->nbucket);

        for (uint32_t i = 0; i < sh->nbucket; i++) {
            auto r = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(r)) {
                sh->buckets[i] = n00b_result_get(r);
            }
        }
    }

    if (sh->nchain > 0) {
        sh->chains = n00b_alloc_array(uint32_t, sh->nchain);

        for (uint32_t i = 0; i < sh->nchain; i++) {
            auto r = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(r)) {
                sh->chains[i] = n00b_result_get(r);
            }
        }
    }

    bin->sysv_hash = sh;
}

// ============================================================================
// parse_symbol_versions
// ============================================================================

static void
parse_symbol_versions(n00b_bstream_t *stream, n00b_elf_binary_t *bin)
{
    // .gnu.version (DT_VERSYM) — parallel to .dynsym.
    uint64_t versym_vaddr = find_dynamic_val(bin, DT_VERSYM);

    if (versym_vaddr != 0 && bin->num_dynsym > 0) {
        uint64_t versym_off = 0;

        if (vaddr_to_offset(bin, versym_vaddr, &versym_off)) {
            bin->sym_versions     = n00b_alloc_array(n00b_elf_symbol_version_t,
                                                     bin->num_dynsym);
            bin->num_sym_versions = bin->num_dynsym;

            n00b_bstream_setpos(stream, versym_off);

            for (uint32_t i = 0; i < bin->num_dynsym; i++) {
                auto r = n00b_bstream_read_u16(stream);

                if (n00b_result_is_ok(r)) {
                    bin->sym_versions[i].value = n00b_result_get(r);
                }
            }
        }
    }

    // Get dynstr info for resolving names.
    uint64_t strtab_vaddr = find_dynamic_val(bin, DT_STRTAB);
    uint64_t strsz        = find_dynamic_val(bin, DT_STRSZ);
    uint64_t strtab_off   = 0;

    if (strtab_vaddr != 0) {
        vaddr_to_offset(bin, strtab_vaddr, &strtab_off);
    }

    // .gnu.version_r (DT_VERNEED).
    uint64_t verneed_vaddr = find_dynamic_val(bin, DT_VERNEED);
    uint64_t verneednum    = find_dynamic_val(bin, DT_VERNEEDNUM);

    if (verneed_vaddr != 0 && verneednum > 0) {
        uint64_t verneed_off = 0;

        if (vaddr_to_offset(bin, verneed_vaddr, &verneed_off)) {
            bin->verneed     = n00b_alloc_array(n00b_elf_verneed_t,
                                                (uint32_t)verneednum);
            bin->num_verneed = (uint32_t)verneednum;

            // First pass: count total aux entries.
            uint32_t total_aux = 0;
            size_t   cur_off   = verneed_off;

            for (uint32_t i = 0; i < (uint32_t)verneednum; i++) {
                n00b_bstream_setpos(stream, cur_off);

                n00b_bstream_read_u16(stream); // vn_version

                auto cnt_r = n00b_bstream_read_u16(stream);

                if (n00b_result_is_ok(cnt_r)) {
                    total_aux += n00b_result_get(cnt_r);
                }

                n00b_bstream_read_u32(stream); // vn_file
                n00b_bstream_read_u32(stream); // vn_aux

                auto next_r = n00b_bstream_read_u32(stream);

                if (n00b_result_is_ok(next_r)) {
                    uint32_t next = n00b_result_get(next_r);

                    if (next == 0) {
                        break;
                    }

                    cur_off += next;
                }
                else {
                    break;
                }
            }

            if (total_aux > 0) {
                bin->vernaux     = n00b_alloc_array(n00b_elf_vernaux_t,
                                                    total_aux);
                bin->num_vernaux = 0;
            }

            // Second pass: read entries.
            cur_off = verneed_off;

            for (uint32_t i = 0; i < (uint32_t)verneednum; i++) {
                n00b_bstream_setpos(stream, cur_off);

                auto ver_r  = n00b_bstream_read_u16(stream);
                auto cnt_r  = n00b_bstream_read_u16(stream);
                auto file_r = n00b_bstream_read_u32(stream);
                auto aux_r  = n00b_bstream_read_u32(stream);
                auto next_r = n00b_bstream_read_u32(stream);

                n00b_elf_verneed_t *vn = &bin->verneed[i];

                if (n00b_result_is_ok(ver_r)) {
                    vn->version = n00b_result_get(ver_r);
                }

                if (n00b_result_is_ok(cnt_r)) {
                    vn->cnt = n00b_result_get(cnt_r);
                }

                if (n00b_result_is_ok(file_r) && strtab_off != 0 && strsz != 0) {
                    vn->file = dynstr_get(stream, strtab_off, strsz,
                                          n00b_result_get(file_r));
                }

                // Read aux entries.
                if (n00b_result_is_ok(aux_r) && n00b_result_is_ok(cnt_r)) {
                    size_t aux_off = cur_off + n00b_result_get(aux_r);

                    for (uint16_t j = 0; j < n00b_result_get(cnt_r); j++) {
                        if (bin->num_vernaux >= total_aux) {
                            break;
                        }

                        n00b_bstream_setpos(stream, aux_off);

                        auto hash_r  = n00b_bstream_read_u32(stream);
                        auto flags_r = n00b_bstream_read_u16(stream);
                        auto other_r = n00b_bstream_read_u16(stream);
                        auto name_r  = n00b_bstream_read_u32(stream);
                        auto anext_r = n00b_bstream_read_u32(stream);

                        n00b_elf_vernaux_t *va = &bin->vernaux[bin->num_vernaux];

                        if (n00b_result_is_ok(hash_r)) {
                            va->hash = n00b_result_get(hash_r);
                        }

                        if (n00b_result_is_ok(flags_r)) {
                            va->flags = n00b_result_get(flags_r);
                        }

                        if (n00b_result_is_ok(other_r)) {
                            va->other = n00b_result_get(other_r);
                        }

                        if (n00b_result_is_ok(name_r) && strtab_off != 0
                            && strsz != 0) {
                            va->name = dynstr_get(stream, strtab_off, strsz,
                                                  n00b_result_get(name_r));
                        }

                        bin->num_vernaux++;

                        if (n00b_result_is_ok(anext_r)) {
                            uint32_t anext = n00b_result_get(anext_r);

                            if (anext == 0) {
                                break;
                            }

                            aux_off += anext;
                        }
                        else {
                            break;
                        }
                    }
                }

                if (n00b_result_is_ok(next_r)) {
                    uint32_t next = n00b_result_get(next_r);

                    if (next == 0) {
                        break;
                    }

                    cur_off += next;
                }
                else {
                    break;
                }
            }
        }
    }

    // .gnu.version_d (DT_VERDEF).
    uint64_t verdef_vaddr = find_dynamic_val(bin, DT_VERDEF);
    uint64_t verdefnum    = find_dynamic_val(bin, DT_VERDEFNUM);

    if (verdef_vaddr != 0 && verdefnum > 0) {
        uint64_t verdef_off = 0;

        if (vaddr_to_offset(bin, verdef_vaddr, &verdef_off)) {
            bin->verdefs     = n00b_alloc_array(n00b_elf_verdef_t,
                                                (uint32_t)verdefnum);
            bin->num_verdefs = (uint32_t)verdefnum;

            size_t cur_off = verdef_off;

            for (uint32_t i = 0; i < (uint32_t)verdefnum; i++) {
                n00b_bstream_setpos(stream, cur_off);

                auto ver_r   = n00b_bstream_read_u16(stream);
                auto flags_r = n00b_bstream_read_u16(stream);
                auto ndx_r   = n00b_bstream_read_u16(stream);
                auto cnt_r   = n00b_bstream_read_u16(stream);
                auto hash_r  = n00b_bstream_read_u32(stream);
                auto aux_r   = n00b_bstream_read_u32(stream);
                auto next_r  = n00b_bstream_read_u32(stream);

                n00b_elf_verdef_t *vd = &bin->verdefs[i];

                if (n00b_result_is_ok(ver_r))   vd->version = n00b_result_get(ver_r);
                if (n00b_result_is_ok(flags_r)) vd->flags   = n00b_result_get(flags_r);
                if (n00b_result_is_ok(ndx_r))   vd->ndx     = n00b_result_get(ndx_r);
                if (n00b_result_is_ok(cnt_r))   vd->cnt     = n00b_result_get(cnt_r);
                if (n00b_result_is_ok(hash_r))  vd->hash    = n00b_result_get(hash_r);

                // Read first verdaux entry to get the name.
                if (n00b_result_is_ok(aux_r)) {
                    size_t aux_off = cur_off + n00b_result_get(aux_r);

                    n00b_bstream_setpos(stream, aux_off);

                    auto vda_name_r = n00b_bstream_read_u32(stream);

                    if (n00b_result_is_ok(vda_name_r) && strtab_off != 0
                        && strsz != 0) {
                        vd->name = dynstr_get(stream, strtab_off, strsz,
                                              n00b_result_get(vda_name_r));
                    }
                }

                if (n00b_result_is_ok(next_r)) {
                    uint32_t next = n00b_result_get(next_r);

                    if (next == 0) {
                        break;
                    }

                    cur_off += next;
                }
                else {
                    break;
                }
            }
        }
    }
}

// ============================================================================
// parse_notes
// ============================================================================

// Helper: count notes in a file range [range_off, range_off + range_size).
static uint32_t
count_notes_in_range(n00b_bstream_t *stream, size_t range_off, size_t range_size)
{
    uint32_t count   = 0;
    size_t   pos     = range_off;
    size_t   end_off = range_off + range_size;

    while (pos + sizeof(n00b_elf64_nhdr_t) <= end_off) {
        n00b_bstream_setpos(stream, pos);

        auto namesz_r = n00b_bstream_read_u32(stream);
        auto descsz_r = n00b_bstream_read_u32(stream);

        if (n00b_result_is_err(namesz_r) || n00b_result_is_err(descsz_r)) {
            break;
        }

        uint32_t namesz = n00b_result_get(namesz_r);
        uint32_t descsz = n00b_result_get(descsz_r);

        n00b_bstream_advance(stream, 4); // n_type

        uint32_t name_aligned = (namesz + 3) & ~3u;
        uint32_t desc_aligned = (descsz + 3) & ~3u;

        pos += sizeof(n00b_elf64_nhdr_t) + name_aligned + desc_aligned;
        count++;
    }

    return count;
}

static void
parse_notes(n00b_bstream_t *stream, n00b_elf_binary_t *bin)
{
    // Prefer SHT_NOTE sections when available.  Fall back to PT_NOTE
    // segments when there are no section headers (e.g. core dumps
    // stripped of section headers).
    bool use_segments = (bin->num_sections == 0);

    if (!use_segments) {
        // Check if any SHT_NOTE section exists.
        bool found_note_section = false;
        for (uint32_t i = 0; i < bin->num_sections; i++) {
            if (bin->sections[i].type == SHT_NOTE && bin->sections[i].size > 0) {
                found_note_section = true;
                break;
            }
        }
        if (!found_note_section) {
            use_segments = true;
        }
    }

    // First pass: count notes.
    uint32_t total = 0;

    if (use_segments) {
        for (uint32_t i = 0; i < bin->num_segments; i++) {
            if (bin->segments[i].type != PT_NOTE || bin->segments[i].filesz == 0) {
                continue;
            }
            total += count_notes_in_range(stream, bin->segments[i].offset,
                                          bin->segments[i].filesz);
        }
    }
    else {
        for (uint32_t i = 0; i < bin->num_sections; i++) {
            if (bin->sections[i].type != SHT_NOTE || bin->sections[i].size == 0) {
                continue;
            }
            total += count_notes_in_range(stream, bin->sections[i].offset,
                                          bin->sections[i].size);
        }
    }

    if (total == 0) {
        return;
    }

    bin->notes     = n00b_alloc_array(n00b_elf_note_t, total);
    bin->num_notes = 0;

    // Macro to avoid duplicating the second-pass read loop.
    #define READ_NOTES_FROM_RANGE(range_off, range_size) do {           \
        size_t sec_off = (range_off);                                   \
        size_t sec_end = sec_off + (range_size);                        \
        size_t pos     = sec_off;                                       \
        READ_NOTES_INNER                                                \
    } while (0)

    // Second pass: read notes.  The inner loop is shared between both
    // section-based and segment-based paths via the macro above.
    #define READ_NOTES_INNER                                            \
        while (pos + sizeof(n00b_elf64_nhdr_t) <= sec_end) {            \
            n00b_bstream_setpos(stream, pos);                            \
                                                                        \
            auto namesz_r = n00b_bstream_read_u32(stream);               \
            auto descsz_r = n00b_bstream_read_u32(stream);               \
            auto type_r   = n00b_bstream_read_u32(stream);               \
                                                                        \
            if (n00b_result_is_err(namesz_r)                            \
                || n00b_result_is_err(descsz_r)                         \
                || n00b_result_is_err(type_r)) {                        \
                break;                                                  \
            }                                                           \
                                                                        \
            uint32_t namesz = n00b_result_get(namesz_r);                \
            uint32_t descsz = n00b_result_get(descsz_r);                \
                                                                        \
            uint32_t name_aligned = (namesz + 3) & ~3u;                 \
            uint32_t desc_aligned = (descsz + 3) & ~3u;                 \
                                                                        \
            n00b_elf_note_t *note = &bin->notes[bin->num_notes];        \
            note->type = n00b_result_get(type_r);                       \
                                                                        \
            if (namesz > 0) {                                           \
                uint32_t name_len = namesz;                             \
                if (name_len > 0) name_len--;                           \
                auto nr = n00b_bstream_read_bytes(stream, name_len);     \
                if (n00b_result_is_ok(nr)) {                            \
                    n00b_buffer_t *nbuf = n00b_result_get(nr);          \
                    note->name = n00b_string_from_raw(nbuf->data,       \
                                                      (int64_t)name_len); \
                }                                                       \
                n00b_bstream_setpos(stream,                              \
                    pos + sizeof(n00b_elf64_nhdr_t) + name_aligned);    \
            }                                                           \
                                                                        \
            if (descsz > 0) {                                           \
                auto dr = n00b_bstream_read_bytes(stream, descsz);       \
                if (n00b_result_is_ok(dr)) {                            \
                    note->desc = n00b_result_get(dr);                   \
                }                                                       \
            }                                                           \
                                                                        \
            pos += sizeof(n00b_elf64_nhdr_t) + name_aligned             \
                   + desc_aligned;                                      \
            bin->num_notes++;                                           \
                                                                        \
            if (bin->num_notes >= total) break;                         \
        }

    if (use_segments) {
        for (uint32_t i = 0; i < bin->num_segments; i++) {
            if (bin->segments[i].type != PT_NOTE
                || bin->segments[i].filesz == 0) {
                continue;
            }
            READ_NOTES_FROM_RANGE(bin->segments[i].offset,
                                  bin->segments[i].filesz);
        }
    }
    else {
        for (uint32_t i = 0; i < bin->num_sections; i++) {
            if (bin->sections[i].type != SHT_NOTE
                || bin->sections[i].size == 0) {
                continue;
            }

            READ_NOTES_FROM_RANGE(bin->sections[i].offset,
                                  bin->sections[i].size);
        }
    }

    #undef READ_NOTES_INNER
    #undef READ_NOTES_FROM_RANGE
}

// ============================================================================
// parse_core_notes — structured interpretation of core dump notes
// ============================================================================

static void
parse_core_notes(n00b_elf_binary_t *bin)
{
    if (bin->header.type != ET_CORE || bin->num_notes == 0) {
        return;
    }

    n00b_elf_core_info_t *ci = n00b_alloc(n00b_elf_core_info_t);

    // First pass: count prstatus and auxv entries.
    uint32_t prs_count = 0;
    uint32_t auxv_count = 0;

    for (uint32_t i = 0; i < bin->num_notes; i++) {
        n00b_elf_note_t *note = &bin->notes[i];

        if (!note->name || !note->name->data) continue;

        bool is_core = (strcmp(note->name->data, "CORE") == 0
                     || strcmp(note->name->data, "LINUX") == 0);

        if (!is_core) continue;

        if (note->type == NT_PRSTATUS) {
            prs_count++;
        }
        else if (note->type == NT_AUXV && note->desc) {
            size_t desc_len = (size_t)n00b_buffer_len(note->desc);
            auxv_count += (uint32_t)(desc_len / 16);  // Each entry is 16 bytes.
        }
    }

    if (prs_count > 0) {
        ci->prstatus = n00b_alloc_array(n00b_elf_prstatus_t, prs_count);
    }

    if (auxv_count > 0) {
        ci->auxv = n00b_alloc_array(n00b_elf_auxv_entry_t, auxv_count);
    }

    // Second pass: parse.
    for (uint32_t i = 0; i < bin->num_notes; i++) {
        n00b_elf_note_t *note = &bin->notes[i];

        if (!note->name || !note->name->data || !note->desc) continue;

        bool is_core = (strcmp(note->name->data, "CORE") == 0
                     || strcmp(note->name->data, "LINUX") == 0);

        if (!is_core) continue;

        const uint8_t *d = (const uint8_t *)note->desc->data;
        size_t dlen = (size_t)n00b_buffer_len(note->desc);

        // Architecture-dependent offsets for prstatus/prpsinfo.
        // The common header fields (signal, pid, etc.) are at the same
        // offsets across architectures, but registers start at different
        // positions and prpsinfo has different minimum sizes.
        //
        //                 prstatus_min  regs_off  prpsinfo_min  fname_off  psargs_off
        //   x86_64:         112          112        136            40          56
        //   aarch64:        112          112        136            40          56
        //   i386:            72           72         124            28          44
        //   (32-bit uses 4-byte timeval fields; 64-bit uses 8-byte)
        //
        // Since we only support ELF64, x86_64 and aarch64 share the same
        // layout.  We use 112/136 for 64-bit and note it in the architecture
        // field for future 32-bit support.
        size_t prstatus_min  = 112;
        size_t regs_off      = 112;
        size_t prpsinfo_min  = 136;
        size_t fname_off     = 40;
        size_t psargs_off    = 56;

        switch (note->type) {
        case NT_PRSTATUS: {
            if (dlen < prstatus_min) break;

            n00b_elf_prstatus_t *ps = &ci->prstatus[ci->num_prstatus];

            // Common prstatus header (same layout for all 64-bit arches):
            //   siginfo (12 bytes): si_signo(4), si_code(4), si_errno(4)
            //   cursig(2), pad(2), sigpend(8), sighold(8)
            //   pid(4), ppid(4), pgrp(4), sid(4)
            //   utime(16), stime(16), cutime(16), cstime(16)
            //   => registers at regs_off
            memcpy(&ps->signal, d + 0, 4);  // si_signo
            memcpy(&ps->pid,    d + 24, 4);
            memcpy(&ps->ppid,   d + 28, 4);
            memcpy(&ps->pgrp,   d + 32, 4);
            memcpy(&ps->sid,    d + 36, 4);

            // Registers: everything from regs_off to end.
            if (dlen > regs_off) {
                size_t reg_size = dlen - regs_off;
                ps->registers = n00b_buffer_new(reg_size);
                memcpy(ps->registers->data, d + regs_off, reg_size);
                ps->registers->byte_len = reg_size;
            }

            ci->num_prstatus++;
            break;
        }

        case NT_PRPSINFO: {
            if (dlen < prpsinfo_min) break;

            n00b_elf_prpsinfo_t *pi = n00b_alloc(n00b_elf_prpsinfo_t);

            // Common prpsinfo header:
            //   state(1), sname(1), zombie(1), nice(1)
            //   flag(8), uid(4), gid(4), pid(4), ppid(4), pgrp(4), sid(4)
            //   fname[16] at fname_off, psargs[80] at psargs_off
            pi->state  = d[0];
            pi->sname  = (char)d[1];
            pi->zombie = d[2];
            pi->nice   = (int8_t)d[3];
            memcpy(&pi->uid,  d + 12, 4);
            memcpy(&pi->gid,  d + 16, 4);
            memcpy(&pi->pid,  d + 20, 4);
            memcpy(&pi->ppid, d + 24, 4);
            memcpy(&pi->pgrp, d + 28, 4);
            memcpy(&pi->sid,  d + 32, 4);
            memcpy(pi->fname, d + fname_off, 16);
            pi->fname[15] = '\0';
            memcpy(pi->psargs, d + psargs_off, 80);
            pi->psargs[79] = '\0';

            ci->prpsinfo = pi;
            break;
        }

        case NT_AUXV: {
            size_t n_entries = dlen / 16;

            for (size_t j = 0; j < n_entries && ci->num_auxv < auxv_count; j++) {
                uint64_t atype, aval;
                memcpy(&atype, d + j * 16, 8);
                memcpy(&aval,  d + j * 16 + 8, 8);

                if (atype == 0) break;  // AT_NULL terminates.

                ci->auxv[ci->num_auxv].type  = atype;
                ci->auxv[ci->num_auxv].value = aval;
                ci->num_auxv++;
            }
            break;
        }

        case NT_FILE: {
            if (dlen < 16) break;

            uint64_t count, page_size;
            memcpy(&count,     d, 8);
            memcpy(&page_size, d + 8, 8);

            if (count > 100000 || 16 + count * 24 > dlen) break;

            ci->files = n00b_alloc_array(n00b_elf_file_entry_t, (uint32_t)count);

            // Entries: start(8), end(8), offset(8) repeated count times,
            // then NUL-terminated filenames.
            const uint8_t *entry_base = d + 16;
            const uint8_t *name_base  = d + 16 + count * 24;
            size_t name_avail = dlen - (size_t)(name_base - d);

            for (uint64_t j = 0; j < count; j++) {
                const uint8_t *e = entry_base + j * 24;
                memcpy(&ci->files[ci->num_files].start,  e, 8);
                memcpy(&ci->files[ci->num_files].end,    e + 8, 8);
                memcpy(&ci->files[ci->num_files].offset, e + 16, 8);

                // Scale offset by page_size.
                ci->files[ci->num_files].offset *= page_size;

                // Find the j-th NUL-terminated string.
                if (name_avail > 0) {
                    size_t slen = strnlen((const char *)name_base, name_avail);
                    ci->files[ci->num_files].name = n00b_string_from_raw(
                        (const char *)name_base, (int64_t)slen);
                    name_base  += slen + 1;
                    name_avail -= slen + 1;
                }

                ci->num_files++;
            }
            break;
        }

        default:
            break;
        }
    }

    bin->core_info = ci;
}

// ============================================================================
// parse_overlay
// ============================================================================

static void
parse_overlay(n00b_bstream_t *stream, n00b_elf_binary_t *bin)
{
    // Find the highest file offset used by any section or segment.
    uint64_t max_end = 0;

    for (uint32_t i = 0; i < bin->num_sections; i++) {
        if (bin->sections[i].type != SHT_NOBITS) {
            uint64_t end = bin->sections[i].offset + bin->sections[i].size;

            if (end > max_end) {
                max_end = end;
            }
        }
    }

    for (uint32_t i = 0; i < bin->num_segments; i++) {
        uint64_t end = bin->segments[i].offset + bin->segments[i].filesz;

        if (end > max_end) {
            max_end = end;
        }
    }

    // Account for the section header table at the end of the file.
    uint64_t shdr_end = bin->header.shoff
                      + (uint64_t)bin->header.shnum * bin->header.shentsize;
    if (shdr_end > max_end) {
        max_end = shdr_end;
    }

    size_t file_size = n00b_buffer_len(stream->buf);

    if (max_end < file_size) {
        size_t overlay_size = file_size - max_end;

        auto r = n00b_bstream_peek_bytes(stream, max_end, overlay_size);

        if (n00b_result_is_ok(r)) {
            bin->overlay = n00b_result_get(r);
        }
    }
}

static n00b_result_t(n00b_elf_binary_t *)
parse_elf_stream(n00b_bstream_t *stream)
{
    n00b_elf_binary_t *bin = n00b_alloc(n00b_elf_binary_t);

    bin->stream = stream;

    // 1. Parse header.
    auto hdr_r = parse_header(stream, bin);

    if (n00b_result_is_err(hdr_r)) {
        return n00b_result_err(n00b_elf_binary_t *, n00b_result_get_err(hdr_r));
    }

    // 2. Parse sections.
    parse_sections(stream, bin);

    // 3. Parse segments.
    parse_segments(stream, bin);

    // 4. Parse dynamic table.
    parse_dynamic_table(stream, bin);

    // 5. Parse dynsym (uses dynamic table info).
    parse_dynsym(stream, bin);

    // 6. Parse symtab.
    parse_symtab(stream, bin);

    // 7. Parse relocations.
    parse_relocations(stream, bin);

    // 8. Parse GNU hash.
    parse_gnu_hash(stream, bin);

    // 9. Parse SYSV hash.
    parse_sysv_hash(stream, bin);

    // 10. Parse symbol versions.
    parse_symbol_versions(stream, bin);

    // 11. Parse notes.
    parse_notes(stream, bin);

    // 12. Parse core dump notes (structured).
    parse_core_notes(bin);

    // 13. Parse overlay.
    parse_overlay(stream, bin);

    // 14. Auto-demangle symbol names.
    for (uint32_t i = 0; i < bin->num_symtab; i++) {
        n00b_elf_symbol_t *sym = &bin->symtab_symbols[i];
        if (sym->name && sym->name->data && n00b_is_mangled(sym->name->data)) {
            sym->demangled_name = n00b_demangle(sym->name->data);
        }
    }
    for (uint32_t i = 0; i < bin->num_dynsym; i++) {
        n00b_elf_symbol_t *sym = &bin->dynsym_symbols[i];
        if (sym->name && sym->name->data && n00b_is_mangled(sym->name->data)) {
            sym->demangled_name = n00b_demangle(sym->name->data);
        }
    }

    return n00b_result_ok(n00b_elf_binary_t *, bin);
}

// ============================================================================
// Top-level ELF parser
// ============================================================================

n00b_result_t(n00b_elf_binary_t *)
n00b_elf_parse(n00b_bstream_t *stream) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!stream) {
        return n00b_result_err(n00b_elf_binary_t *, N00B_ERR_READ);
    }

    n00b_allocator_t *effective_allocator =
        allocator ? allocator : stream->allocator;

    if (effective_allocator != nullptr) {
        stream->allocator = effective_allocator;

        n00b_allocator_t *previous =
            n00b_set_current_allocator(effective_allocator);
        auto result = parse_elf_stream(stream);
        n00b_restore_current_allocator(previous);

        return result;
    }

    return parse_elf_stream(stream);
}

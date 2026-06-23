#include <string.h>

#include "compiler/objfile/elf_build.h"

// ============================================================================
// Alignment helper
// ============================================================================

static inline size_t
align_up(size_t v, size_t align)
{
    if (align <= 1) {
        return v;
    }

    return (v + align - 1) & ~(align - 1);
}

// ============================================================================
// File offset to virtual address helper
// ============================================================================

static uint64_t
file_off_to_vaddr(n00b_elf_binary_t *bin, uint64_t offset)
{
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_elf_segment_t *seg = &bin->segments[i];

        if (seg->type == PT_LOAD
            && offset >= seg->offset
            && offset < seg->offset + seg->filesz) {
            return seg->vaddr + (offset - seg->offset);
        }
    }

    // Fallback: return the raw offset (works when vaddr == offset).
    return offset;
}

// ============================================================================
// ELF64 on-disk sizes
// ============================================================================

#define N00B_ELF64_EHDR_SIZE  64
#define N00B_ELF64_PHDR_SIZE  56
#define N00B_ELF64_SHDR_SIZE  64
#define N00B_ELF64_SYM_SIZE   24
#define N00B_ELF64_REL_SIZE   16
#define N00B_ELF64_RELA_SIZE  24
#define N00B_ELF64_DYN_SIZE   16
#define N00B_ELF64_NHDR_SIZE  12

// ============================================================================
// Write helpers
// ============================================================================

static void
write_ehdr(n00b_writer_t *w, n00b_elf_header_t *h)
{
    n00b_writer_write_bytes(w, h->ident, 16);
    n00b_writer_write_u16(w, h->type);
    n00b_writer_write_u16(w, h->machine);
    n00b_writer_write_u32(w, h->version);
    n00b_writer_write_u64(w, h->entry);
    n00b_writer_write_u64(w, h->phoff);
    n00b_writer_write_u64(w, h->shoff);
    n00b_writer_write_u32(w, h->flags);
    n00b_writer_write_u16(w, h->ehsize);
    n00b_writer_write_u16(w, h->phentsize);
    n00b_writer_write_u16(w, h->phnum);
    n00b_writer_write_u16(w, h->shentsize);
    n00b_writer_write_u16(w, h->shnum);
    n00b_writer_write_u16(w, h->shstrndx);
}

static void
write_phdr(n00b_writer_t *w, n00b_elf_segment_t *seg)
{
    n00b_writer_write_u32(w, seg->type);
    n00b_writer_write_u32(w, seg->flags);
    n00b_writer_write_u64(w, seg->offset);
    n00b_writer_write_u64(w, seg->vaddr);
    n00b_writer_write_u64(w, seg->paddr);
    n00b_writer_write_u64(w, seg->filesz);
    n00b_writer_write_u64(w, seg->memsz);
    n00b_writer_write_u64(w, seg->align);
}

static void
write_shdr(n00b_writer_t *w, uint32_t name_off, uint32_t type, uint64_t flags,
           uint64_t addr, uint64_t offset, uint64_t size,
           uint32_t link, uint32_t info, uint64_t addralign, uint64_t entsize)
{
    n00b_writer_write_u32(w, name_off);
    n00b_writer_write_u32(w, type);
    n00b_writer_write_u64(w, flags);
    n00b_writer_write_u64(w, addr);
    n00b_writer_write_u64(w, offset);
    n00b_writer_write_u64(w, size);
    n00b_writer_write_u32(w, link);
    n00b_writer_write_u32(w, info);
    n00b_writer_write_u64(w, addralign);
    n00b_writer_write_u64(w, entsize);
}

static void
write_sym(n00b_writer_t *w, uint32_t name_off, uint8_t info, uint8_t other,
          uint16_t shndx, uint64_t value, uint64_t size)
{
    n00b_writer_write_u32(w, name_off);
    n00b_writer_write_u8(w, info);
    n00b_writer_write_u8(w, other);
    n00b_writer_write_u16(w, shndx);
    n00b_writer_write_u64(w, value);
    n00b_writer_write_u64(w, size);
}

static void
write_rel(n00b_writer_t *w, n00b_elf_relocation_t *rel)
{
    n00b_writer_write_u64(w, rel->offset);
    n00b_writer_write_u64(w, rel->info);
}

static void
write_rela(n00b_writer_t *w, n00b_elf_relocation_t *rel)
{
    n00b_writer_write_u64(w, rel->offset);
    n00b_writer_write_u64(w, rel->info);
    n00b_writer_write_i64(w, rel->addend);
}

static void
write_dyn(n00b_writer_t *w, int64_t tag, uint64_t value)
{
    n00b_writer_write_i64(w, tag);
    n00b_writer_write_u64(w, value);
}

// ============================================================================
// GNU hash generation
// ============================================================================

static uint32_t
gnu_hash(const char *name)
{
    uint32_t h = 5381;

    const uint8_t *p;
    for (p = (const uint8_t *)name; *p; p++) {
        h = (h << 5) + h + *p;
    }

    return h;
}

static void
build_gnu_hash(n00b_writer_t *w, n00b_elf_symbol_t *syms, uint32_t nsyms,
               uint32_t *name_offsets, uint32_t *out_size,
               n00b_allocator_t *allocator)
{
    // Count hashable (non-local) symbols.
    uint32_t first_global = 0;

    for (uint32_t i = 0; i < nsyms; i++) {
        if (N00B_ELF64_ST_BIND(syms[i].info) != STB_LOCAL) {
            break;
        }
        first_global++;
    }

    uint32_t num_globals = nsyms - first_global;

    if (num_globals == 0) {
        // Minimal empty hash table: nbuckets=1, symoffset=nsyms, bloom_size=1,
        // bloom_shift=0, 1 bloom word (0), 1 bucket (0), 0 chains.
        n00b_writer_write_u32(w, 1);      // nbuckets
        n00b_writer_write_u32(w, nsyms);  // symoffset
        n00b_writer_write_u32(w, 1);      // bloom_size
        n00b_writer_write_u32(w, 0);      // bloom_shift
        n00b_writer_write_u64(w, 0);      // bloom[0]
        n00b_writer_write_u32(w, 0);      // bucket[0]
        *out_size = 4 * 4 + 8 + 4;       // 28 bytes
        return;
    }

    // Choose nbuckets: next power of 2 >= num_globals, capped at 1024.
    uint32_t nbuckets = 1;

    while (nbuckets < num_globals && nbuckets < 1024) {
        nbuckets <<= 1;
    }

    uint32_t symoffset   = first_global;
    uint32_t bloom_size  = 1;
    uint32_t bloom_shift = 6;

    // Compute hashes.
    uint32_t *hashes = n00b_alloc_array_with_opts(
        uint32_t,
        num_globals,
        &(n00b_alloc_opts_t){ .allocator = allocator });

    for (uint32_t i = 0; i < num_globals; i++) {
        const char *name = syms[first_global + i].name ? syms[first_global + i].name->data : nullptr;
        hashes[i] = name ? gnu_hash(name) : 0;
    }

    // Build bloom filter (single word for simplicity).
    uint64_t bloom = 0;

    for (uint32_t i = 0; i < num_globals; i++) {
        uint32_t h = hashes[i];
        bloom |= (uint64_t)1 << (h % 64);
        bloom |= (uint64_t)1 << ((h >> bloom_shift) % 64);
    }

    // Sort global symbols by bucket index so that symbols in the same
    // bucket are contiguous — required by the GNU hash table format.
    // We build a permutation array and reorder symbols + hashes.
    uint32_t *order = n00b_alloc_array_with_opts(
        uint32_t,
        num_globals,
        &(n00b_alloc_opts_t){ .allocator = allocator });

    for (uint32_t i = 0; i < num_globals; i++) {
        order[i] = i;
    }

    // Simple insertion sort by bucket (stable, preserves intra-bucket order).
    for (uint32_t i = 1; i < num_globals; i++) {
        uint32_t key = order[i];
        uint32_t key_bucket = hashes[key] % nbuckets;
        int j = (int)i - 1;

        while (j >= 0 && (hashes[order[j]] % nbuckets) > key_bucket) {
            order[j + 1] = order[j];
            j--;
        }
        order[j + 1] = key;
    }

    // Reorder hashes according to the permutation.
    uint32_t *sorted_hashes = n00b_alloc_array_with_opts(
        uint32_t,
        num_globals,
        &(n00b_alloc_opts_t){ .allocator = allocator });

    for (uint32_t i = 0; i < num_globals; i++) {
        sorted_hashes[i] = hashes[order[i]];
    }

    // Reorder the actual symbol array in-place.
    // Build inverse permutation, then cycle-sort.
    n00b_elf_symbol_t *tmp_syms = n00b_alloc_array_with_opts(
        n00b_elf_symbol_t,
        num_globals,
        &(n00b_alloc_opts_t){ .allocator = allocator });

    for (uint32_t i = 0; i < num_globals; i++) {
        tmp_syms[i] = syms[first_global + order[i]];
    }

    memcpy(&syms[first_global], tmp_syms, num_globals * sizeof(n00b_elf_symbol_t));

    // Use sorted hashes from now on.
    memcpy(hashes, sorted_hashes, num_globals * sizeof(uint32_t));

    // Build buckets and chains.
    uint32_t *buckets = n00b_alloc_array_with_opts(
        uint32_t,
        nbuckets,
        &(n00b_alloc_opts_t){ .allocator = allocator });
    uint32_t *chains  = n00b_alloc_array_with_opts(
        uint32_t,
        num_globals,
        &(n00b_alloc_opts_t){ .allocator = allocator });
    // Buckets point to the first symbol in each bucket group.
    for (uint32_t i = 0; i < num_globals; i++) {
        uint32_t bucket = hashes[i] % nbuckets;

        if (buckets[bucket] == 0) {
            buckets[bucket] = symoffset + i;
        }
    }

    // Chain values: hash with low bit cleared, low bit = 1 if last in bucket.
    for (uint32_t i = 0; i < num_globals; i++) {
        bool is_last = (i + 1 >= num_globals)
                    || (hashes[i + 1] % nbuckets) != (hashes[i] % nbuckets);
        chains[i] = (hashes[i] & ~1u) | (is_last ? 1 : 0);
    }

    // Write the hash table.
    n00b_writer_write_u32(w, nbuckets);
    n00b_writer_write_u32(w, symoffset);
    n00b_writer_write_u32(w, bloom_size);
    n00b_writer_write_u32(w, bloom_shift);
    n00b_writer_write_u64(w, bloom);

    for (uint32_t i = 0; i < nbuckets; i++) {
        n00b_writer_write_u32(w, buckets[i]);
    }

    for (uint32_t i = 0; i < num_globals; i++) {
        n00b_writer_write_u32(w, chains[i]);
    }

    *out_size = 4 * 4 + 8 * bloom_size + 4 * nbuckets + 4 * num_globals;
    (void)name_offsets;
}

// ============================================================================
// Note serialization
// ============================================================================

static size_t
note_serialized_size(n00b_elf_note_t *note)
{
    uint32_t namesz = (note->name && note->name->data) ? (uint32_t)(note->name->u8_bytes + 1) : 0;
    uint32_t descsz = note->desc ? (uint32_t)n00b_buffer_len(note->desc) : 0;

    return N00B_ELF64_NHDR_SIZE + align_up(namesz, 4) + align_up(descsz, 4);
}

static void
write_note(n00b_writer_t *w, n00b_elf_note_t *note)
{
    uint32_t namesz = (note->name && note->name->data) ? (uint32_t)(note->name->u8_bytes + 1) : 0;
    uint32_t descsz = note->desc ? (uint32_t)n00b_buffer_len(note->desc) : 0;

    n00b_writer_write_u32(w, namesz);
    n00b_writer_write_u32(w, descsz);
    n00b_writer_write_u32(w, note->type);

    if (namesz > 0) {
        n00b_writer_write_bytes(w, note->name->data, namesz);
        // Align to 4 bytes.
        size_t pad = align_up(namesz, 4) - namesz;
        if (pad > 0) {
            n00b_writer_write_zeros(w, pad);
        }
    }

    if (descsz > 0) {
        n00b_writer_write_bytes(w, note->desc->data, descsz);
        size_t pad = align_up(descsz, 4) - descsz;
        if (pad > 0) {
            n00b_writer_write_zeros(w, pad);
        }
    }
}

// ============================================================================
// Version tables serialization
// ============================================================================

static void
write_versym(n00b_writer_t *w, n00b_elf_binary_t *bin)
{
    for (uint32_t i = 0; i < bin->num_sym_versions; i++) {
        n00b_writer_write_u16(w, bin->sym_versions[i].value);
    }
}

static size_t
write_verneed(n00b_writer_t *w, n00b_elf_binary_t *bin,
              n00b_strtab_builder_t *dynstr)
{
    size_t start = n00b_writer_pos(w);

    uint32_t aux_idx = 0;

    for (uint32_t i = 0; i < bin->num_verneed; i++) {
        n00b_elf_verneed_t *vn = &bin->verneed[i];

        uint32_t file_off = n00b_strtab_builder_add(dynstr, vn->file ? vn->file->data : "");
        uint32_t aux_off_from_here = 16; // Fixed size of verneed entry.
        uint32_t next_off = (i + 1 < bin->num_verneed)
            ? (uint32_t)(16 + vn->cnt * 16)
            : 0;

        n00b_writer_write_u16(w, vn->version);
        n00b_writer_write_u16(w, vn->cnt);
        n00b_writer_write_u32(w, file_off);
        n00b_writer_write_u32(w, aux_off_from_here);
        n00b_writer_write_u32(w, next_off);

        for (uint32_t j = 0; j < vn->cnt && aux_idx < bin->num_vernaux; j++) {
            n00b_elf_vernaux_t *va = &bin->vernaux[aux_idx];
            uint32_t name_off = n00b_strtab_builder_add(dynstr, va->name ? va->name->data : "");
            uint32_t next_aux = (j + 1 < vn->cnt) ? 16 : 0;

            n00b_writer_write_u32(w, va->hash);
            n00b_writer_write_u16(w, va->flags);
            n00b_writer_write_u16(w, va->other);
            n00b_writer_write_u32(w, name_off);
            n00b_writer_write_u32(w, next_aux);
            aux_idx++;
        }
    }

    return n00b_writer_pos(w) - start;
}

static size_t
write_verdef(n00b_writer_t *w, n00b_elf_binary_t *bin,
             n00b_strtab_builder_t *dynstr)
{
    size_t start = n00b_writer_pos(w);

    for (uint32_t i = 0; i < bin->num_verdefs; i++) {
        n00b_elf_verdef_t *vd = &bin->verdefs[i];
        uint32_t name_off = n00b_strtab_builder_add(dynstr, vd->name ? vd->name->data : "");

        uint32_t aux_off  = 20; // sizeof vd fields.
        uint32_t next_off = (i + 1 < bin->num_verdefs) ? (uint32_t)(20 + 8) : 0;

        n00b_writer_write_u16(w, vd->version);
        n00b_writer_write_u16(w, vd->flags);
        n00b_writer_write_u16(w, vd->ndx);
        n00b_writer_write_u16(w, vd->cnt);
        n00b_writer_write_u32(w, vd->hash);
        n00b_writer_write_u32(w, aux_off);
        n00b_writer_write_u32(w, next_off);

        // Auxiliary entry: just the name.
        n00b_writer_write_u32(w, name_off);
        n00b_writer_write_u32(w, 0); // vda_next
    }

    return n00b_writer_pos(w) - start;
}

// ============================================================================
// Main build function
// ============================================================================

n00b_result_t(n00b_buffer_t *)
n00b_elf_build(n00b_elf_binary_t *bin) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!bin) {
        return n00b_result_err(n00b_buffer_t *, N00B_ERR_BUILD);
    }

    // -----------------------------------------------------------------------
    // 1. Build string tables
    // -----------------------------------------------------------------------

    n00b_strtab_builder_t *shstrtab = n00b_strtab_builder_new(
        .allocator = allocator);
    n00b_strtab_builder_t *strtab   = n00b_strtab_builder_new(
        .allocator = allocator);
    n00b_strtab_builder_t *dynstr   = nullptr;

    bool has_dynsym     = bin->num_dynsym > 0;
    bool has_dynamic    = bin->num_dynamic > 0 || has_dynsym;
    bool has_symtab     = bin->num_symtab > 0;
    bool has_relocs     = bin->num_relocations > 0;
    bool use_rela       = false;

    // Use RELA if any relocation has an explicit addend.
    for (uint32_t i = 0; i < bin->num_relocations; i++) {
        if (bin->relocations[i].has_addend) {
            use_rela = true;
            break;
        }
    }
    bool has_notes      = bin->num_notes > 0;
    bool has_interp     = bin->interpreter && bin->interpreter->data && bin->interpreter->u8_bytes > 0;
    bool has_gnu_hash   = has_dynsym;
    bool has_versym     = bin->num_sym_versions > 0;
    bool has_verneed    = bin->num_verneed > 0;
    bool has_verdef     = bin->num_verdefs > 0;

    if (has_dynsym || has_dynamic) {
        dynstr = n00b_strtab_builder_new(.allocator = allocator);
    }

    // Register names for user-provided sections in shstrtab.
    uint32_t *user_sec_name_offs = nullptr;

    if (bin->num_sections > 0) {
        user_sec_name_offs = n00b_alloc_array_with_opts(
            uint32_t,
            bin->num_sections,
            &(n00b_alloc_opts_t){ .allocator = allocator });

        for (uint32_t i = 0; i < bin->num_sections; i++) {
            if (bin->sections[i].name && bin->sections[i].name->data) {
                user_sec_name_offs[i] = n00b_strtab_builder_add(
                    shstrtab, bin->sections[i].name->data);
            }
        }
    }

    // Register symtab symbol names in strtab.
    uint32_t *symtab_name_offs = nullptr;

    if (has_symtab) {
        symtab_name_offs = n00b_alloc_array_with_opts(
            uint32_t,
            bin->num_symtab,
            &(n00b_alloc_opts_t){ .allocator = allocator });

        for (uint32_t i = 0; i < bin->num_symtab; i++) {
            if (bin->symtab_symbols[i].name && bin->symtab_symbols[i].name->data) {
                symtab_name_offs[i] = n00b_strtab_builder_add(
                    strtab, bin->symtab_symbols[i].name->data);
            }
        }
    }

    // Register dynsym symbol names in dynstr.
    uint32_t *dynsym_name_offs = nullptr;

    if (has_dynsym) {
        dynsym_name_offs = n00b_alloc_array_with_opts(
            uint32_t,
            bin->num_dynsym,
            &(n00b_alloc_opts_t){ .allocator = allocator });

        for (uint32_t i = 0; i < bin->num_dynsym; i++) {
            if (bin->dynsym_symbols[i].name && bin->dynsym_symbols[i].name->data) {
                dynsym_name_offs[i] = n00b_strtab_builder_add(
                    dynstr, bin->dynsym_symbols[i].name->data);
            }
        }
    }

    // Register DT_NEEDED strings in dynstr.
    if (has_dynamic && dynstr) {
        for (uint32_t i = 0; i < bin->num_dynamic; i++) {
            if (bin->dynamic_entries[i].tag == DT_NEEDED) {
                // The value is a string offset — we need to ensure the name
                // exists.  The caller should have already populated the value.
                // For round-trip, we preserve the existing value.
            }
        }
    }

    // Register synthetic section names.
    uint32_t shstrtab_name_off = n00b_strtab_builder_add(shstrtab, ".shstrtab");
    uint32_t strtab_name_off   = 0;
    uint32_t symtab_name_off   = 0;
    uint32_t dynstr_name_off   = 0;
    uint32_t dynsym_name_off   = 0;
    uint32_t dynamic_name_off  = 0;
    uint32_t rela_name_off     = 0;
    uint32_t gnu_hash_name_off = 0;
    uint32_t interp_name_off   = 0;
    uint32_t note_name_off     = 0;
    uint32_t versym_name_off   = 0;
    uint32_t verneed_name_off  = 0;
    uint32_t verdef_name_off   = 0;

    if (has_symtab) {
        strtab_name_off = n00b_strtab_builder_add(shstrtab, ".strtab");
        symtab_name_off = n00b_strtab_builder_add(shstrtab, ".symtab");
    }

    if (has_dynsym) {
        dynstr_name_off  = n00b_strtab_builder_add(shstrtab, ".dynstr");
        dynsym_name_off  = n00b_strtab_builder_add(shstrtab, ".dynsym");
    }
    else if (dynstr) {
        dynstr_name_off = n00b_strtab_builder_add(shstrtab, ".dynstr");
    }

    if (has_dynamic) {
        dynamic_name_off = n00b_strtab_builder_add(shstrtab, ".dynamic");
    }

    if (has_relocs) {
        rela_name_off = n00b_strtab_builder_add(shstrtab,
                            use_rela ? ".rela.dyn" : ".rel.dyn");
    }

    if (has_gnu_hash) {
        gnu_hash_name_off = n00b_strtab_builder_add(shstrtab, ".gnu.hash");
    }

    if (has_interp) {
        interp_name_off = n00b_strtab_builder_add(shstrtab, ".interp");
    }

    if (has_notes) {
        note_name_off = n00b_strtab_builder_add(shstrtab, ".note");
    }

    if (has_versym) {
        versym_name_off = n00b_strtab_builder_add(shstrtab, ".gnu.version");
    }

    if (has_verneed) {
        verneed_name_off = n00b_strtab_builder_add(shstrtab,
                                                     ".gnu.version_r");
    }

    if (has_verdef) {
        verdef_name_off = n00b_strtab_builder_add(shstrtab,
                                                    ".gnu.version_d");
    }

    // -----------------------------------------------------------------------
    // 2. Count synthetic sections
    // -----------------------------------------------------------------------

    uint32_t num_synth_sections = 1; // .shstrtab always

    if (has_symtab)   num_synth_sections += 2; // .symtab + .strtab
    if (has_dynsym)   num_synth_sections += 2; // .dynsym + .dynstr
    else if (dynstr)  num_synth_sections += 1; // .dynstr alone (dynamic without dynsym)
    if (has_dynamic)  num_synth_sections += 1;
    if (has_relocs)   num_synth_sections += 1;
    if (has_gnu_hash) num_synth_sections += 1;
    if (has_interp)   num_synth_sections += 1;
    if (has_notes)    num_synth_sections += 1;
    if (has_versym)   num_synth_sections += 1;
    if (has_verneed)  num_synth_sections += 1;
    if (has_verdef)   num_synth_sections += 1;

    // Total sections: NULL + user sections + synthetic sections.
    uint32_t total_sections = 1 + bin->num_sections + num_synth_sections;

    // -----------------------------------------------------------------------
    // 3. Layout computation
    // -----------------------------------------------------------------------

    // We lay out segments for PT_INTERP, PT_DYNAMIC, PT_NOTE, PT_GNU_STACK,
    // PT_GNU_RELRO in addition to user segments.

    uint32_t extra_segments = 0;

    if (has_interp)  extra_segments++;
    if (has_dynamic) extra_segments++;
    if (has_notes)   extra_segments++;

    uint32_t total_segments = bin->num_segments + extra_segments;
    size_t   pos            = N00B_ELF64_EHDR_SIZE;

    // Program headers right after ELF header.
    size_t phdr_off = pos;
    pos += (size_t)total_segments * N00B_ELF64_PHDR_SIZE;

    // Align to 16 bytes for section data.
    pos = align_up(pos, 16);

    // --- Interp section ---
    size_t interp_off  = 0;
    size_t interp_size = 0;

    if (has_interp) {
        interp_off  = pos;
        interp_size = bin->interpreter->u8_bytes + 1; // include NUL
        pos += interp_size;
        pos = align_up(pos, 8);
    }

    // --- Note section ---
    size_t note_off  = 0;
    size_t note_size = 0;

    if (has_notes) {
        note_off = pos;

        for (uint32_t i = 0; i < bin->num_notes; i++) {
            note_size += note_serialized_size(&bin->notes[i]);
        }

        pos += note_size;
        pos = align_up(pos, 8);
    }

    // --- GNU hash section ---
    // We'll write it later and record size; for now, reserve space.
    size_t gnu_hash_off  = 0;
    size_t gnu_hash_size = 0;

    if (has_gnu_hash) {
        gnu_hash_off = pos;
        // Estimate size; we'll patch later.
        // Conservative estimate for layout: header + bloom + buckets + chains
        uint32_t num_globals = 0;

        for (uint32_t i = 0; i < bin->num_dynsym; i++) {
            if (N00B_ELF64_ST_BIND(bin->dynsym_symbols[i].info) != STB_LOCAL) {
                num_globals++;
            }
        }

        uint32_t nbuckets = 1;

        while (nbuckets < num_globals && nbuckets < 1024) {
            nbuckets <<= 1;
        }

        if (num_globals == 0) {
            gnu_hash_size = 28;
        }
        else {
            gnu_hash_size = 4 * 4 + 8 + 4 * nbuckets + 4 * num_globals;
        }

        pos += gnu_hash_size;
        pos = align_up(pos, 8);
    }

    // --- Dynsym section ---
    size_t dynsym_off  = 0;
    size_t dynsym_size = 0;

    if (has_dynsym) {
        dynsym_off  = pos;
        dynsym_size = (size_t)bin->num_dynsym * N00B_ELF64_SYM_SIZE;
        pos += dynsym_size;
        pos = align_up(pos, 8);
    }

    // --- Versym section ---
    size_t versym_off  = 0;
    size_t versym_size = 0;

    if (has_versym) {
        versym_off  = pos;
        versym_size = (size_t)bin->num_sym_versions * 2;
        pos += versym_size;
        pos = align_up(pos, 8);
    }

    // --- Dynstr section ---
    size_t dynstr_off  = 0;
    size_t dynstr_size = 0;

    // We need to pre-generate verneed/verdef to populate dynstr.
    // First pass: add all verneed/verdef names to dynstr.
    if (has_verneed && dynstr) {
        for (uint32_t i = 0; i < bin->num_verneed; i++) {
            if (bin->verneed[i].file && bin->verneed[i].file->data) {
                n00b_strtab_builder_add(dynstr, bin->verneed[i].file->data);
            }
        }

        for (uint32_t i = 0; i < bin->num_vernaux; i++) {
            if (bin->vernaux[i].name && bin->vernaux[i].name->data) {
                n00b_strtab_builder_add(dynstr, bin->vernaux[i].name->data);
            }
        }
    }

    if (has_verdef && dynstr) {
        for (uint32_t i = 0; i < bin->num_verdefs; i++) {
            if (bin->verdefs[i].name && bin->verdefs[i].name->data) {
                n00b_strtab_builder_add(dynstr, bin->verdefs[i].name->data);
            }
        }
    }

    if (dynstr) {
        dynstr_off  = pos;
        dynstr_size = n00b_strtab_builder_size(dynstr);
        pos += dynstr_size;
        pos = align_up(pos, 8);
    }

    // --- Rela section ---
    size_t rela_off  = 0;
    size_t rela_size = 0;

    if (has_relocs) {
        rela_off  = pos;
        size_t entry_sz = use_rela ? N00B_ELF64_RELA_SIZE : N00B_ELF64_REL_SIZE;
        rela_size = (size_t)bin->num_relocations * entry_sz;
        pos += rela_size;
        pos = align_up(pos, 8);
    }

    // --- Dynamic section ---
    size_t dynamic_off  = 0;
    size_t dynamic_size = 0;

    // Count auto-generated DT entries needed when dynsym present.
    uint32_t auto_dyn_count = 0;

    if (has_dynsym) {
        // DT_SYMTAB, DT_STRTAB, DT_STRSZ always needed.
        auto_dyn_count += 3;
        if (has_gnu_hash) auto_dyn_count += 1; // DT_GNU_HASH
    }

    if (has_dynamic) {
        dynamic_off  = pos;
        // +1 for DT_NULL terminator + auto-generated entries.
        dynamic_size = (size_t)(bin->num_dynamic + auto_dyn_count + 1)
                     * N00B_ELF64_DYN_SIZE;
        pos += dynamic_size;
        pos = align_up(pos, 8);
    }

    // --- Verneed section ---
    size_t verneed_off  = 0;
    size_t verneed_size = 0;

    if (has_verneed) {
        verneed_off = pos;
        // Size: each verneed is 16 bytes, each vernaux is 16 bytes.
        verneed_size = (size_t)bin->num_verneed * 16
                     + (size_t)bin->num_vernaux * 16;
        pos += verneed_size;
        pos = align_up(pos, 8);
    }

    // --- Verdef section ---
    size_t verdef_off  = 0;
    size_t verdef_size = 0;

    if (has_verdef) {
        verdef_off = pos;
        // Each verdef: 20 bytes + 8 bytes aux.
        verdef_size = (size_t)bin->num_verdefs * 28;
        pos += verdef_size;
        pos = align_up(pos, 8);
    }

    // --- User section data ---
    size_t *user_sec_offsets = nullptr;

    if (bin->num_sections > 0) {
        user_sec_offsets = n00b_alloc_array_with_opts(
            size_t,
            bin->num_sections,
            &(n00b_alloc_opts_t){ .allocator = allocator });

        for (uint32_t i = 0; i < bin->num_sections; i++) {
            uint64_t addralign = bin->sections[i].addralign;

            if (addralign > 1) {
                pos = align_up(pos, addralign);
            }

            user_sec_offsets[i] = pos;

            if (bin->sections[i].content) {
                pos += n00b_buffer_len(bin->sections[i].content);
            }
            else if (bin->sections[i].type != SHT_NOBITS) {
                pos += bin->sections[i].size;
            }
        }

        pos = align_up(pos, 8);
    }

    // --- Symtab ---
    size_t symtab_off  = 0;
    size_t symtab_size = 0;

    if (has_symtab) {
        symtab_off  = pos;
        symtab_size = (size_t)bin->num_symtab * N00B_ELF64_SYM_SIZE;
        pos += symtab_size;
        pos = align_up(pos, 8);
    }

    // --- Strtab ---
    size_t strtab_off  = 0;
    size_t strtab_size = 0;

    if (has_symtab) {
        strtab_off  = pos;
        strtab_size = n00b_strtab_builder_size(strtab);
        pos += strtab_size;
        pos = align_up(pos, 8);
    }

    // --- Shstrtab ---
    size_t shstrtab_off  = pos;
    size_t shstrtab_size = n00b_strtab_builder_size(shstrtab);
    pos += shstrtab_size;
    pos = align_up(pos, 8);

    // --- Section header table ---
    size_t shdr_off = pos;
    pos += (size_t)total_sections * N00B_ELF64_SHDR_SIZE;

    // -----------------------------------------------------------------------
    // 4. Determine section indices for link fields
    // -----------------------------------------------------------------------

    // Section ordering:
    //   [0] SHT_NULL
    //   [1..num_sections] user sections
    //   then synthetic sections in a defined order
    uint16_t idx = (uint16_t)(1 + bin->num_sections);

    uint16_t interp_shndx   = 0;
    uint16_t note_shndx     = 0;
    uint16_t gnu_hash_shndx = 0;
    uint16_t dynsym_shndx   = 0;
    uint16_t versym_shndx   = 0;
    uint16_t dynstr_shndx   = 0;
    uint16_t rela_shndx     = 0;
    uint16_t dynamic_shndx  = 0;
    uint16_t verneed_shndx  = 0;
    uint16_t verdef_shndx   = 0;
    uint16_t symtab_shndx   = 0;
    uint16_t strtab_shndx   = 0;
    uint16_t shstrtab_shndx = 0;

    if (has_interp)   { interp_shndx   = idx++; }
    if (has_notes)    { note_shndx     = idx++; }
    if (has_gnu_hash) { gnu_hash_shndx = idx++; }
    if (has_dynsym)   { dynsym_shndx   = idx++; }
    if (has_versym)   { versym_shndx   = idx++; }
    if (dynstr)       { dynstr_shndx   = idx++; }
    if (has_relocs)   { rela_shndx     = idx++; }
    if (has_dynamic)  { dynamic_shndx  = idx++; }
    if (has_verneed)  { verneed_shndx  = idx++; }
    if (has_verdef)   { verdef_shndx   = idx++; }
    if (has_symtab)   { symtab_shndx   = idx++; strtab_shndx = idx++; }
    shstrtab_shndx = idx++;

    // -----------------------------------------------------------------------
    // 5. Fix up header and segments
    // -----------------------------------------------------------------------

    // Fix up PT_LOAD segments to cover the file content so that
    // vaddr_to_offset works correctly when parsing back.
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        if (bin->segments[i].type == PT_LOAD) {
            if (bin->segments[i].filesz == 0) {
                bin->segments[i].filesz = pos;
            }

            if (bin->segments[i].memsz == 0) {
                bin->segments[i].memsz = pos;
            }
        }
    }

    bin->header.phoff    = phdr_off;
    bin->header.shoff    = shdr_off;
    bin->header.phnum    = (uint16_t)total_segments;
    bin->header.shnum    = (uint16_t)total_sections;
    bin->header.shstrndx = shstrtab_shndx;

    // -----------------------------------------------------------------------
    // 6. Serialize
    // -----------------------------------------------------------------------

    n00b_writer_t *w = n00b_writer_new(pos + 64, .allocator = allocator);

    // Set endianness from binary.
    if (bin->header.ident[EI_DATA] == ELFDATA2MSB) {
        n00b_writer_set_endian(w, N00B_ENDIAN_BIG);
    }
    else {
        n00b_writer_set_endian(w, N00B_ENDIAN_LITTLE);
    }

    // --- ELF header ---
    write_ehdr(w, &bin->header);

    // --- Program headers ---
    n00b_writer_setpos(w, phdr_off);

    for (uint32_t i = 0; i < bin->num_segments; i++) {
        write_phdr(w, &bin->segments[i]);
    }

    // Synthetic segments.
    if (has_interp) {
        n00b_elf_segment_t interp_seg = {
            .type   = PT_INTERP,
            .flags  = PF_R,
            .offset = interp_off,
            .vaddr  = 0,
            .paddr  = 0,
            .filesz = interp_size,
            .memsz  = interp_size,
            .align  = 1,
        };
        write_phdr(w, &interp_seg);
    }

    if (has_dynamic) {
        n00b_elf_segment_t dyn_seg = {
            .type   = PT_DYNAMIC,
            .flags  = PF_R | PF_W,
            .offset = dynamic_off,
            .vaddr  = 0,
            .paddr  = 0,
            .filesz = dynamic_size,
            .memsz  = dynamic_size,
            .align  = 8,
        };
        write_phdr(w, &dyn_seg);
    }

    if (has_notes) {
        n00b_elf_segment_t note_seg = {
            .type   = PT_NOTE,
            .flags  = PF_R,
            .offset = note_off,
            .vaddr  = 0,
            .paddr  = 0,
            .filesz = note_size,
            .memsz  = note_size,
            .align  = 4,
        };
        write_phdr(w, &note_seg);
    }

    // --- Interp content ---
    if (has_interp) {
        n00b_writer_setpos(w, interp_off);
        n00b_writer_write_bytes(w, bin->interpreter->data,
                                 bin->interpreter->u8_bytes);
        n00b_writer_write_u8(w, 0);
    }

    // --- Note content ---
    if (has_notes) {
        n00b_writer_setpos(w, note_off);

        for (uint32_t i = 0; i < bin->num_notes; i++) {
            write_note(w, &bin->notes[i]);
        }
    }

    // --- GNU hash ---
    if (has_gnu_hash) {
        n00b_writer_setpos(w, gnu_hash_off);
        uint32_t actual_size = 0;
        build_gnu_hash(w, bin->dynsym_symbols, bin->num_dynsym,
                       dynsym_name_offs, &actual_size, allocator);
        gnu_hash_size = actual_size;
    }

    // --- Dynsym ---
    if (has_dynsym) {
        n00b_writer_setpos(w, dynsym_off);

        for (uint32_t i = 0; i < bin->num_dynsym; i++) {
            write_sym(w, dynsym_name_offs[i],
                      bin->dynsym_symbols[i].info,
                      bin->dynsym_symbols[i].other,
                      bin->dynsym_symbols[i].shndx,
                      bin->dynsym_symbols[i].value,
                      bin->dynsym_symbols[i].size);
        }
    }

    // --- Versym ---
    if (has_versym) {
        n00b_writer_setpos(w, versym_off);
        write_versym(w, bin);
    }

    // --- Dynstr ---
    if (dynstr) {
        n00b_writer_setpos(w, dynstr_off);
        n00b_strtab_builder_write(dynstr, w);
    }

    // --- Relocations ---
    if (has_relocs) {
        n00b_writer_setpos(w, rela_off);

        for (uint32_t i = 0; i < bin->num_relocations; i++) {
            if (use_rela) {
                write_rela(w, &bin->relocations[i]);
            }
            else {
                write_rel(w, &bin->relocations[i]);
            }
        }
    }

    // --- Dynamic table ---
    if (has_dynamic) {
        n00b_writer_setpos(w, dynamic_off);

        // Write user-supplied dynamic entries.
        for (uint32_t i = 0; i < bin->num_dynamic; i++) {
            write_dyn(w, bin->dynamic_entries[i].tag,
                      bin->dynamic_entries[i].value);
        }

        // Auto-generate DT entries for dynsym discovery.
        // DT_SYMTAB, DT_STRTAB, DT_GNU_HASH require virtual addresses,
        // not file offsets. DT_STRSZ is a size, not an address.
        if (has_dynsym) {
            write_dyn(w, DT_SYMTAB, file_off_to_vaddr(bin, dynsym_off));
            write_dyn(w, DT_STRTAB, file_off_to_vaddr(bin, dynstr_off));
            write_dyn(w, DT_STRSZ,  dynstr_size);

            if (has_gnu_hash) {
                write_dyn(w, DT_GNU_HASH, file_off_to_vaddr(bin, gnu_hash_off));
            }
        }

        // DT_NULL terminator.
        write_dyn(w, DT_NULL, 0);
    }

    // --- Verneed ---
    if (has_verneed) {
        n00b_writer_setpos(w, verneed_off);
        verneed_size = write_verneed(w, bin, dynstr);
    }

    // --- Verdef ---
    if (has_verdef) {
        n00b_writer_setpos(w, verdef_off);
        verdef_size = write_verdef(w, bin, dynstr);
    }

    // --- User section content ---
    for (uint32_t i = 0; i < bin->num_sections; i++) {
        if (bin->sections[i].content) {
            n00b_writer_setpos(w, user_sec_offsets[i]);
            n00b_writer_write_buffer(w, bin->sections[i].content);
        }
    }

    // --- Symtab ---
    if (has_symtab) {
        n00b_writer_setpos(w, symtab_off);

        for (uint32_t i = 0; i < bin->num_symtab; i++) {
            write_sym(w, symtab_name_offs[i],
                      bin->symtab_symbols[i].info,
                      bin->symtab_symbols[i].other,
                      bin->symtab_symbols[i].shndx,
                      bin->symtab_symbols[i].value,
                      bin->symtab_symbols[i].size);
        }
    }

    // --- Strtab ---
    if (has_symtab) {
        n00b_writer_setpos(w, strtab_off);
        n00b_strtab_builder_write(strtab, w);
    }

    // --- Shstrtab ---
    n00b_writer_setpos(w, shstrtab_off);
    n00b_strtab_builder_write(shstrtab, w);

    // --- Section header table ---
    n00b_writer_setpos(w, shdr_off);

    // [0] SHT_NULL
    write_shdr(w, 0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0);

    // User sections.
    for (uint32_t i = 0; i < bin->num_sections; i++) {
        size_t sec_size = 0;

        if (bin->sections[i].content) {
            sec_size = n00b_buffer_len(bin->sections[i].content);
        }
        else {
            sec_size = bin->sections[i].size;
        }

        write_shdr(w,
                   user_sec_name_offs ? user_sec_name_offs[i] : 0,
                   bin->sections[i].type,
                   bin->sections[i].flags,
                   bin->sections[i].addr,
                   user_sec_offsets ? user_sec_offsets[i] : 0,
                   sec_size,
                   bin->sections[i].link,
                   bin->sections[i].info,
                   bin->sections[i].addralign,
                   bin->sections[i].entsize);
    }

    // Synthetic sections (in the order we assigned indices).
    if (has_interp) {
        write_shdr(w, interp_name_off, SHT_PROGBITS, SHF_ALLOC,
                   0, interp_off, interp_size, 0, 0, 1, 0);
    }

    if (has_notes) {
        write_shdr(w, note_name_off, SHT_NOTE, SHF_ALLOC,
                   0, note_off, note_size, 0, 0, 4, 0);
    }

    if (has_gnu_hash) {
        write_shdr(w, gnu_hash_name_off, SHT_GNU_HASH, SHF_ALLOC,
                   0, gnu_hash_off, gnu_hash_size,
                   dynsym_shndx, 0, 8, 0);
    }

    if (has_dynsym) {
        // Count local symbols for sh_info.
        uint32_t first_global = 0;

        for (uint32_t i = 0; i < bin->num_dynsym; i++) {
            if (N00B_ELF64_ST_BIND(bin->dynsym_symbols[i].info) == STB_LOCAL) {
                first_global++;
            }
            else {
                break;
            }
        }

        write_shdr(w, dynsym_name_off, SHT_DYNSYM, SHF_ALLOC,
                   0, dynsym_off, dynsym_size,
                   dynstr_shndx, first_global, 8, N00B_ELF64_SYM_SIZE);
    }

    if (has_versym) {
        write_shdr(w, versym_name_off, SHT_GNU_VERSYM, SHF_ALLOC,
                   0, versym_off, versym_size,
                   dynsym_shndx, 0, 2, 2);
    }

    if (dynstr) {
        write_shdr(w, dynstr_name_off, SHT_STRTAB, SHF_ALLOC,
                   0, dynstr_off, dynstr_size, 0, 0, 1, 0);
    }

    if (has_relocs) {
        uint32_t rel_type    = use_rela ? SHT_RELA : SHT_REL;
        uint64_t rel_entsize = use_rela ? N00B_ELF64_RELA_SIZE : N00B_ELF64_REL_SIZE;

        write_shdr(w, rela_name_off, rel_type, SHF_ALLOC,
                   0, rela_off, rela_size,
                   has_dynsym ? dynsym_shndx : 0, 0, 8, rel_entsize);
    }

    if (has_dynamic) {
        write_shdr(w, dynamic_name_off, SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE,
                   0, dynamic_off, dynamic_size,
                   dynstr ? dynstr_shndx : 0, 0, 8, N00B_ELF64_DYN_SIZE);
    }

    if (has_verneed) {
        write_shdr(w, verneed_name_off, SHT_GNU_VERNEED, SHF_ALLOC,
                   0, verneed_off, verneed_size,
                   dynstr_shndx, bin->num_verneed, 8, 0);
    }

    if (has_verdef) {
        write_shdr(w, verdef_name_off, SHT_GNU_VERDEF, SHF_ALLOC,
                   0, verdef_off, verdef_size,
                   dynstr_shndx, bin->num_verdefs, 8, 0);
    }

    if (has_symtab) {
        // Count local symbols for sh_info.
        uint32_t first_global = 0;

        for (uint32_t i = 0; i < bin->num_symtab; i++) {
            if (N00B_ELF64_ST_BIND(bin->symtab_symbols[i].info) == STB_LOCAL) {
                first_global++;
            }
            else {
                break;
            }
        }

        write_shdr(w, symtab_name_off, SHT_SYMTAB, 0,
                   0, symtab_off, symtab_size,
                   strtab_shndx, first_global, 8, N00B_ELF64_SYM_SIZE);

        write_shdr(w, strtab_name_off, SHT_STRTAB, 0,
                   0, strtab_off, strtab_size, 0, 0, 1, 0);
    }

    // .shstrtab.
    write_shdr(w, shstrtab_name_off, SHT_STRTAB, 0,
               0, shstrtab_off, shstrtab_size, 0, 0, 1, 0);

    // Set final position to the end.
    n00b_writer_setpos(w, pos);

    n00b_buffer_t *result = n00b_writer_finalize(w);

    // Suppress unused-but-set warnings for conditional section indices.
    (void)interp_shndx;
    (void)note_shndx;
    (void)gnu_hash_shndx;
    (void)versym_shndx;
    (void)rela_shndx;
    (void)dynamic_shndx;
    (void)verneed_shndx;
    (void)verdef_shndx;
    (void)symtab_shndx;

    return n00b_result_ok(n00b_buffer_t *, result);
}

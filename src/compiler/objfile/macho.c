#include <string.h>
#include "compiler/objfile/macho.h"
#include "compiler/objfile/demangle.h"

// ============================================================================
// Internal helpers
// ============================================================================

/// Read a big-endian uint32_t from a byte pointer.
static inline uint32_t
cs_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

/// Map MachO cputype to n00b_arch_t.
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

/// Read a string from within a load command at the given command start offset
/// + string offset within the command.
static n00b_string_t *
read_lc_string(n00b_bstream_t *stream, size_t cmd_start, uint32_t cmd_size,
               uint32_t str_offset)
{
    if (str_offset >= cmd_size) {
        return n00b_string_empty();
    }

    size_t saved = n00b_bstream_pos(stream);

    n00b_bstream_setpos(stream, cmd_start + str_offset);

    auto r = n00b_bstream_read_cstring(stream);

    n00b_bstream_setpos(stream, saved);

    if (n00b_result_is_err(r)) {
        return n00b_string_empty();
    }

    return n00b_result_get(r);
}

// ============================================================================
// parse_header
// ============================================================================

static n00b_result_t(bool)
parse_header(n00b_bstream_t *stream, n00b_macho_binary_t *bin)
{
    if (!n00b_bstream_can_read(stream, sizeof(n00b_macho_header64_t))) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }

    size_t header_start = n00b_bstream_pos(stream);

    auto magic_r = n00b_bstream_read_u32(stream);

    if (n00b_result_is_err(magic_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }

    uint32_t magic = n00b_result_get(magic_r);

    // Detect endianness and validate magic.
    if (magic == MH_MAGIC_64) {
        n00b_bstream_set_endian(stream, N00B_ENDIAN_LITTLE);
    }
    else if (magic == MH_CIGAM_64) {
        n00b_bstream_set_endian(stream, N00B_ENDIAN_BIG);
        magic = MH_MAGIC_64;
    }
    else {
        return n00b_result_err(bool, N00B_ERR_NOT_SUPPORTED);
    }

    bin->header.magic = magic;

    // Re-read remaining fields with correct endianness.
    // magic was already read without swap, so we need to re-read from start
    // if we set endianness. Alternatively, continue reading.
    // Since we set endianness after reading magic, re-read from after magic.

    auto cputype_r = n00b_bstream_read_u32(stream);

    if (n00b_result_is_err(cputype_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }
    bin->header.cputype = n00b_result_get(cputype_r);

    auto cpusubtype_r = n00b_bstream_read_u32(stream);

    if (n00b_result_is_err(cpusubtype_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }
    bin->header.cpusubtype = n00b_result_get(cpusubtype_r);

    auto filetype_r = n00b_bstream_read_u32(stream);

    if (n00b_result_is_err(filetype_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }
    bin->header.filetype = n00b_result_get(filetype_r);

    auto ncmds_r = n00b_bstream_read_u32(stream);

    if (n00b_result_is_err(ncmds_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }
    bin->header.ncmds = n00b_result_get(ncmds_r);

    auto sizeofcmds_r = n00b_bstream_read_u32(stream);

    if (n00b_result_is_err(sizeofcmds_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }
    bin->header.sizeofcmds = n00b_result_get(sizeofcmds_r);

    auto flags_r = n00b_bstream_read_u32(stream);

    if (n00b_result_is_err(flags_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }
    bin->header.flags = n00b_result_get(flags_r);

    auto reserved_r = n00b_bstream_read_u32(stream);

    if (n00b_result_is_err(reserved_r)) {
        return n00b_result_err(bool, N00B_ERR_CORRUPTED);
    }
    bin->header.reserved = n00b_result_get(reserved_r);

    (void)header_start;

    return n00b_result_ok(bool, true);
}

// ============================================================================
// parse_segment — single LC_SEGMENT_64
// ============================================================================

static void
parse_segment(n00b_bstream_t *stream, n00b_macho_binary_t *bin,
              size_t cmd_start, uint32_t cmd_size)
{
    // Position is right after cmd + cmdsize (already read by caller).
    // But we need to re-read from the segment-specific fields.
    // The caller sets position to cmd_start + 8 (after cmd + cmdsize).

    // segname[16]
    auto segname_r = n00b_bstream_read_bytes(stream, 16);

    if (n00b_result_is_err(segname_r)) {
        return;
    }

    auto vmaddr_r   = n00b_bstream_read_u64(stream);
    auto vmsize_r   = n00b_bstream_read_u64(stream);
    auto fileoff_r  = n00b_bstream_read_u64(stream);
    auto filesize_r = n00b_bstream_read_u64(stream);
    auto maxprot_r  = n00b_bstream_read_u32(stream);
    auto initprot_r = n00b_bstream_read_u32(stream);
    auto nsects_r   = n00b_bstream_read_u32(stream);
    auto sflags_r   = n00b_bstream_read_u32(stream);

    // Grow the segments array.
    uint32_t idx = bin->num_segments;

    bin->num_segments++;

    n00b_macho_segment_t *new_segs = n00b_alloc_array(n00b_macho_segment_t,
                                                      bin->num_segments);

    if (idx > 0) {
        memcpy(new_segs, bin->segments,
               idx * sizeof(n00b_macho_segment_t));
    }

    bin->segments = new_segs;

    n00b_macho_segment_t *seg = &bin->segments[idx];

    // Copy segname (null-terminated).
    n00b_buffer_t *name_buf = n00b_result_get(segname_r);

    memset(seg->name, 0, sizeof(seg->name));
    memcpy(seg->name, name_buf->data,
           n00b_buffer_len(name_buf) < 16 ? n00b_buffer_len(name_buf) : 16);

    if (n00b_result_is_ok(vmaddr_r))   seg->vmaddr   = n00b_result_get(vmaddr_r);
    if (n00b_result_is_ok(vmsize_r))   seg->vmsize   = n00b_result_get(vmsize_r);
    if (n00b_result_is_ok(fileoff_r))  seg->fileoff  = n00b_result_get(fileoff_r);
    if (n00b_result_is_ok(filesize_r)) seg->filesize = n00b_result_get(filesize_r);
    if (n00b_result_is_ok(maxprot_r))  seg->maxprot  = n00b_result_get(maxprot_r);
    if (n00b_result_is_ok(initprot_r)) seg->initprot = n00b_result_get(initprot_r);
    if (n00b_result_is_ok(nsects_r))   seg->nsects   = n00b_result_get(nsects_r);
    if (n00b_result_is_ok(sflags_r))   seg->flags    = n00b_result_get(sflags_r);

    // Read segment content.
    if (seg->filesize > 0) {
        size_t actual_off = bin->fat_offset + seg->fileoff;

        auto cr = n00b_bstream_peek_bytes(stream, actual_off, seg->filesize);

        if (n00b_result_is_ok(cr)) {
            seg->content = n00b_result_get(cr);
        }
    }

    // Read sections (clamp to prevent absurd allocations from crafted binaries).
    if (seg->nsects > 4096) {
        seg->nsects = 4096;
    }

    if (seg->nsects > 0) {
        seg->sections = n00b_alloc_array(n00b_macho_section_t, seg->nsects);

        for (uint32_t i = 0; i < seg->nsects; i++) {
            n00b_macho_section_t *sec = &seg->sections[i];

            // sectname[16]
            auto sn_r = n00b_bstream_read_bytes(stream, 16);

            if (n00b_result_is_ok(sn_r)) {
                n00b_buffer_t *snbuf = n00b_result_get(sn_r);

                memset(sec->sectname, 0, sizeof(sec->sectname));
                memcpy(sec->sectname, snbuf->data,
                       n00b_buffer_len(snbuf) < 16
                       ? n00b_buffer_len(snbuf) : 16);
            }

            // segname[16]
            auto sgn_r = n00b_bstream_read_bytes(stream, 16);

            if (n00b_result_is_ok(sgn_r)) {
                n00b_buffer_t *sgnbuf = n00b_result_get(sgn_r);

                memset(sec->segname, 0, sizeof(sec->segname));
                memcpy(sec->segname, sgnbuf->data,
                       n00b_buffer_len(sgnbuf) < 16
                       ? n00b_buffer_len(sgnbuf) : 16);
            }

            auto addr_r  = n00b_bstream_read_u64(stream);
            auto size_r  = n00b_bstream_read_u64(stream);
            auto off_r   = n00b_bstream_read_u32(stream);
            auto align_r = n00b_bstream_read_u32(stream);
            auto reloff_r = n00b_bstream_read_u32(stream);
            auto nreloc_r = n00b_bstream_read_u32(stream);
            auto secflags_r = n00b_bstream_read_u32(stream);
            auto r1_r    = n00b_bstream_read_u32(stream);
            auto r2_r    = n00b_bstream_read_u32(stream);
            auto r3_r    = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(addr_r))     sec->addr      = n00b_result_get(addr_r);
            if (n00b_result_is_ok(size_r))     sec->size      = n00b_result_get(size_r);
            if (n00b_result_is_ok(off_r))      sec->offset    = n00b_result_get(off_r);
            if (n00b_result_is_ok(align_r))    sec->align     = n00b_result_get(align_r);
            if (n00b_result_is_ok(reloff_r))   sec->reloff    = n00b_result_get(reloff_r);
            if (n00b_result_is_ok(nreloc_r))   sec->nreloc    = n00b_result_get(nreloc_r);
            if (n00b_result_is_ok(secflags_r)) sec->flags     = n00b_result_get(secflags_r);
            if (n00b_result_is_ok(r1_r))       sec->reserved1 = n00b_result_get(r1_r);
            if (n00b_result_is_ok(r2_r))       sec->reserved2 = n00b_result_get(r2_r);
            if (n00b_result_is_ok(r3_r))       sec->reserved3 = n00b_result_get(r3_r);

            // Read section content.
            if (sec->size > 0 && sec->offset > 0) {
                size_t sec_actual_off = bin->fat_offset + sec->offset;

                auto scr = n00b_bstream_peek_bytes(stream, sec_actual_off,
                                                  sec->size);

                if (n00b_result_is_ok(scr)) {
                    sec->content = n00b_result_get(scr);
                }
            }
        }
    }

    (void)cmd_size;
}

// ============================================================================
// parse_symbols
// ============================================================================

static void
parse_symbols(n00b_bstream_t *stream, n00b_macho_binary_t *bin,
              uint32_t symoff, uint32_t nsyms,
              uint32_t stroff, uint32_t strsize)
{
    if (nsyms == 0 || symoff == 0) {
        return;
    }

    size_t actual_symoff = bin->fat_offset + symoff;
    size_t actual_stroff = bin->fat_offset + stroff;

    // Load string table.
    n00b_buffer_t *strtab = nullptr;

    if (strsize > 0) {
        auto sr = n00b_bstream_peek_bytes(stream, actual_stroff, strsize);

        if (n00b_result_is_ok(sr)) {
            strtab = n00b_result_get(sr);
        }
    }

    bin->symbols     = n00b_alloc_array(n00b_macho_symbol_t, nsyms);
    bin->num_symbols = nsyms;

    n00b_bstream_setpos(stream, actual_symoff);

    for (uint32_t i = 0; i < nsyms; i++) {
        n00b_macho_symbol_t *sym = &bin->symbols[i];

        auto strx_r  = n00b_bstream_read_u32(stream);
        auto type_r  = n00b_bstream_read_u8(stream);
        auto sect_r  = n00b_bstream_read_u8(stream);
        auto desc_r  = n00b_bstream_read_u16(stream);
        auto value_r = n00b_bstream_read_u64(stream);

        if (n00b_result_is_ok(type_r))  sym->type  = n00b_result_get(type_r);
        if (n00b_result_is_ok(sect_r))  sym->sect  = n00b_result_get(sect_r);
        if (n00b_result_is_ok(desc_r))  sym->desc  = n00b_result_get(desc_r);
        if (n00b_result_is_ok(value_r)) sym->value = n00b_result_get(value_r);

        if (n00b_result_is_ok(strx_r) && strtab) {
            uint32_t strx = n00b_result_get(strx_r);

            if (strx < (uint32_t)n00b_buffer_len(strtab)) {
                const char *base = strtab->data + strx;
                size_t      max  = n00b_buffer_len(strtab) - strx;
                size_t      len  = strnlen(base, max);

                sym->name = n00b_string_from_raw(base, (int64_t)len);
            }
        }
    }
}

// ============================================================================
// parse_indirect_symbols
// ============================================================================

static void
parse_indirect_symbols(n00b_bstream_t *stream, n00b_macho_binary_t *bin,
                       uint32_t indirectsymoff, uint32_t nindirectsyms)
{
    if (nindirectsyms == 0 || indirectsymoff == 0) {
        return;
    }

    size_t actual_off = bin->fat_offset + indirectsymoff;

    bin->indirect_symbols     = n00b_alloc_array(uint32_t, nindirectsyms);
    bin->num_indirect_symbols = nindirectsyms;

    n00b_bstream_setpos(stream, actual_off);

    for (uint32_t i = 0; i < nindirectsyms; i++) {
        auto r = n00b_bstream_read_u32(stream);

        if (n00b_result_is_ok(r)) {
            bin->indirect_symbols[i] = n00b_result_get(r);
        }
    }
}

// ============================================================================
// parse_relocations — for all sections
// ============================================================================

static void
parse_relocations(n00b_bstream_t *stream, n00b_macho_binary_t *bin)
{
    for (uint32_t si = 0; si < bin->num_segments; si++) {
        n00b_macho_segment_t *seg = &bin->segments[si];

        for (uint32_t se = 0; se < seg->nsects; se++) {
            n00b_macho_section_t *sec = &seg->sections[se];

            if (sec->nreloc == 0 || sec->reloff == 0) {
                continue;
            }

            size_t actual_off = bin->fat_offset + sec->reloff;

            sec->relocations     = n00b_alloc_array(n00b_macho_relocation_t,
                                                    sec->nreloc);
            sec->num_relocations = sec->nreloc;

            n00b_bstream_setpos(stream, actual_off);

            for (uint32_t i = 0; i < sec->nreloc; i++) {
                n00b_macho_relocation_t *rel = &sec->relocations[i];

                auto addr_r = n00b_bstream_read_i32(stream);
                auto info_r = n00b_bstream_read_u32(stream);

                if (n00b_result_is_ok(addr_r)) {
                    rel->address = n00b_result_get(addr_r);
                }

                if (n00b_result_is_ok(info_r)) {
                    uint32_t info = n00b_result_get(info_r);

                    // Decode bitfields.
                    // For non-scattered: symbolnum=24 bits, pcrel=1, length=2,
                    //                    extern=1, type=4
                    rel->symbolnum = info & 0x00FFFFFFu;
                    rel->pcrel     = (info >> 24) & 1;
                    rel->length    = (info >> 25) & 3;
                    rel->is_extern = (info >> 27) & 1;
                    rel->type      = (info >> 28) & 0xF;
                    rel->scattered = false;
                }
            }
        }
    }
}

// ============================================================================
// parse_dyld_bindings — decode bind opcodes
// ============================================================================

static uint32_t
decode_bindings(n00b_bstream_t *stream, n00b_macho_binary_t *bin,
                uint32_t bind_off, uint32_t bind_size,
                n00b_macho_binding_t *out, uint32_t out_cap,
                bool is_weak, bool is_lazy)
{
    if (bind_size == 0 || bind_off == 0) {
        return 0;
    }

    size_t actual_off = bin->fat_offset + bind_off;
    size_t end_off    = actual_off + bind_size;

    n00b_bstream_setpos(stream, actual_off);

    uint8_t        type            = BIND_TYPE_POINTER;
    int64_t        addend          = 0;
    n00b_string_t *symbol_name     = n00b_string_empty();
    int32_t        library_ordinal = 0;
    uint8_t        seg_index       = 0;
    uint64_t       seg_offset      = 0;
    uint32_t       count           = 0;

    while (n00b_bstream_pos(stream) < end_off && count < out_cap) {
        auto byte_r = n00b_bstream_read_u8(stream);

        if (n00b_result_is_err(byte_r)) {
            break;
        }

        uint8_t byte    = n00b_result_get(byte_r);
        uint8_t opcode  = byte & BIND_OPCODE_MASK;
        uint8_t imm     = byte & BIND_IMMEDIATE_MASK;

        switch (opcode) {
        case BIND_OPCODE_DONE:
            if (!is_lazy) {
                goto done;
            }
            break;

        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
            library_ordinal = (int32_t)imm;
            break;

        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: {
            auto r = n00b_bstream_read_uleb128(stream);
            if (n00b_result_is_ok(r)) {
                library_ordinal = (int32_t)n00b_result_get(r);
            }
            break;
        }

        case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
            if (imm == 0) {
                library_ordinal = 0;
            }
            else {
                library_ordinal = (int32_t)(int8_t)(0xF0 | imm);
            }
            break;

        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
            auto r = n00b_bstream_read_cstring(stream);
            if (n00b_result_is_ok(r)) {
                symbol_name = n00b_result_get(r);
            }
            break;
        }

        case BIND_OPCODE_SET_TYPE_IMM:
            type = imm;
            break;

        case BIND_OPCODE_SET_ADDEND_SLEB: {
            auto r = n00b_bstream_read_sleb128(stream);
            if (n00b_result_is_ok(r)) {
                addend = n00b_result_get(r);
            }
            break;
        }

        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: {
            seg_index = imm;
            auto r = n00b_bstream_read_uleb128(stream);
            if (n00b_result_is_ok(r)) {
                seg_offset = n00b_result_get(r);
            }
            break;
        }

        case BIND_OPCODE_ADD_ADDR_ULEB: {
            auto r = n00b_bstream_read_uleb128(stream);
            if (n00b_result_is_ok(r)) {
                seg_offset += n00b_result_get(r);
            }
            break;
        }

        case BIND_OPCODE_DO_BIND: {
            if (count < out_cap) {
                uint64_t addr = 0;

                if (seg_index < bin->num_segments) {
                    addr = bin->segments[seg_index].vmaddr + seg_offset;
                }

                out[count].type            = type;
                out[count].addend          = addend;
                out[count].address         = addr;
                out[count].symbol_name     = symbol_name;
                out[count].library_ordinal = library_ordinal;
                out[count].segment_index   = seg_index;
                out[count].is_weak         = is_weak;
                out[count].is_lazy         = is_lazy;
                count++;
            }
            seg_offset += 8;
            break;
        }

        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: {
            if (count < out_cap) {
                uint64_t addr = 0;

                if (seg_index < bin->num_segments) {
                    addr = bin->segments[seg_index].vmaddr + seg_offset;
                }

                out[count].type            = type;
                out[count].addend          = addend;
                out[count].address         = addr;
                out[count].symbol_name     = symbol_name;
                out[count].library_ordinal = library_ordinal;
                out[count].segment_index   = seg_index;
                out[count].is_weak         = is_weak;
                out[count].is_lazy         = is_lazy;
                count++;
            }
            seg_offset += 8;
            auto r = n00b_bstream_read_uleb128(stream);
            if (n00b_result_is_ok(r)) {
                seg_offset += n00b_result_get(r);
            }
            break;
        }

        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: {
            if (count < out_cap) {
                uint64_t addr = 0;

                if (seg_index < bin->num_segments) {
                    addr = bin->segments[seg_index].vmaddr + seg_offset;
                }

                out[count].type            = type;
                out[count].addend          = addend;
                out[count].address         = addr;
                out[count].symbol_name     = symbol_name;
                out[count].library_ordinal = library_ordinal;
                out[count].segment_index   = seg_index;
                out[count].is_weak         = is_weak;
                out[count].is_lazy         = is_lazy;
                count++;
            }
            seg_offset += 8 + (uint64_t)imm * 8;
            break;
        }

        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
            auto times_r = n00b_bstream_read_uleb128(stream);
            auto skip_r  = n00b_bstream_read_uleb128(stream);

            uint64_t times = 0;
            uint64_t skip  = 0;

            if (n00b_result_is_ok(times_r)) times = n00b_result_get(times_r);
            if (n00b_result_is_ok(skip_r))  skip  = n00b_result_get(skip_r);

            for (uint64_t j = 0; j < times && count < out_cap; j++) {
                uint64_t addr = 0;

                if (seg_index < bin->num_segments) {
                    addr = bin->segments[seg_index].vmaddr + seg_offset;
                }

                out[count].type            = type;
                out[count].addend          = addend;
                out[count].address         = addr;
                out[count].symbol_name     = symbol_name;
                out[count].library_ordinal = library_ordinal;
                out[count].segment_index   = seg_index;
                out[count].is_weak         = is_weak;
                out[count].is_lazy         = is_lazy;
                count++;
                seg_offset += 8 + skip;
            }
            break;
        }

        case BIND_OPCODE_THREADED: {
            if (imm == BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB) {
                // Consume the ULEB128 ordinal table size (we don't use it
                // for opcode-based binding, but must consume to keep stream
                // position correct).
                n00b_bstream_read_uleb128(stream);
            }
            // BIND_SUBOPCODE_THREADED_APPLY (imm==1): actual threaded binding
            // is done via chained fixups in __DATA pages, not opcode stream.
            // Nothing to consume for sub-opcode 1.
            break;
        }

        default:
            break;
        }
    }

done:
    return count;
}

// ============================================================================
// parse_rebases — decode rebase opcodes
// ============================================================================

static void
parse_rebases(n00b_bstream_t *stream, n00b_macho_binary_t *bin,
              uint32_t rebase_off, uint32_t rebase_size)
{
    if (rebase_size == 0 || rebase_off == 0) {
        return;
    }

    size_t actual_off = bin->fat_offset + rebase_off;
    size_t end_off    = actual_off + rebase_size;

    // First pass: count rebases.
    n00b_bstream_setpos(stream, actual_off);

    uint32_t total = 0;
    uint8_t  seg_index = 0;

    while (n00b_bstream_pos(stream) < end_off) {
        auto byte_r = n00b_bstream_read_u8(stream);

        if (n00b_result_is_err(byte_r)) {
            break;
        }

        uint8_t byte   = n00b_result_get(byte_r);
        uint8_t opcode = byte & REBASE_OPCODE_MASK;
        uint8_t imm    = byte & REBASE_IMMEDIATE_MASK;

        switch (opcode) {
        case REBASE_OPCODE_DONE:
            goto count_done;

        case REBASE_OPCODE_SET_TYPE_IMM:
            break;

        case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            seg_index = imm;
            n00b_bstream_read_uleb128(stream);
            break;

        case REBASE_OPCODE_ADD_ADDR_ULEB:
            n00b_bstream_read_uleb128(stream);
            break;

        case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
            break;

        case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
            total += imm;
            break;

        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES: {
            auto r = n00b_bstream_read_uleb128(stream);
            if (n00b_result_is_ok(r)) {
                total += (uint32_t)n00b_result_get(r);
            }
            break;
        }

        case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
            total++;
            n00b_bstream_read_uleb128(stream);
            break;

        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: {
            auto r = n00b_bstream_read_uleb128(stream);
            n00b_bstream_read_uleb128(stream); // skip
            if (n00b_result_is_ok(r)) {
                total += (uint32_t)n00b_result_get(r);
            }
            break;
        }

        default:
            break;
        }
    }

count_done:
    if (total == 0) {
        return;
    }

    bin->rebases     = n00b_alloc_array(n00b_macho_rebase_t, total);
    bin->num_rebases = 0;

    // Second pass: decode.
    n00b_bstream_setpos(stream, actual_off);

    uint8_t  rtype      = REBASE_TYPE_POINTER;
    uint64_t seg_offset = 0;

    seg_index = 0;

    while (n00b_bstream_pos(stream) < end_off && bin->num_rebases < total) {
        auto byte_r = n00b_bstream_read_u8(stream);

        if (n00b_result_is_err(byte_r)) {
            break;
        }

        uint8_t byte   = n00b_result_get(byte_r);
        uint8_t opcode = byte & REBASE_OPCODE_MASK;
        uint8_t imm    = byte & REBASE_IMMEDIATE_MASK;

        switch (opcode) {
        case REBASE_OPCODE_DONE:
            goto decode_done;

        case REBASE_OPCODE_SET_TYPE_IMM:
            rtype = imm;
            break;

        case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: {
            seg_index = imm;
            auto r = n00b_bstream_read_uleb128(stream);
            if (n00b_result_is_ok(r)) {
                seg_offset = n00b_result_get(r);
            }
            break;
        }

        case REBASE_OPCODE_ADD_ADDR_ULEB: {
            auto r = n00b_bstream_read_uleb128(stream);
            if (n00b_result_is_ok(r)) {
                seg_offset += n00b_result_get(r);
            }
            break;
        }

        case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
            seg_offset += (uint64_t)imm * 8;
            break;

        case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
            for (uint8_t j = 0; j < imm && bin->num_rebases < total; j++) {
                n00b_macho_rebase_t *rb = &bin->rebases[bin->num_rebases];
                rb->type          = rtype;
                rb->segment_index = seg_index;
                rb->address       = (seg_index < bin->num_segments)
                                  ? bin->segments[seg_index].vmaddr + seg_offset
                                  : 0;
                bin->num_rebases++;
                seg_offset += 8;
            }
            break;

        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES: {
            auto r = n00b_bstream_read_uleb128(stream);
            if (n00b_result_is_ok(r)) {
                uint64_t times = n00b_result_get(r);
                for (uint64_t j = 0;
                     j < times && bin->num_rebases < total; j++) {
                    n00b_macho_rebase_t *rb = &bin->rebases[bin->num_rebases];
                    rb->type          = rtype;
                    rb->segment_index = seg_index;
                    rb->address       = (seg_index < bin->num_segments)
                                      ? bin->segments[seg_index].vmaddr
                                        + seg_offset
                                      : 0;
                    bin->num_rebases++;
                    seg_offset += 8;
                }
            }
            break;
        }

        case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: {
            if (bin->num_rebases < total) {
                n00b_macho_rebase_t *rb = &bin->rebases[bin->num_rebases];
                rb->type          = rtype;
                rb->segment_index = seg_index;
                rb->address       = (seg_index < bin->num_segments)
                                  ? bin->segments[seg_index].vmaddr + seg_offset
                                  : 0;
                bin->num_rebases++;
                seg_offset += 8;
            }
            auto r = n00b_bstream_read_uleb128(stream);
            if (n00b_result_is_ok(r)) {
                seg_offset += n00b_result_get(r);
            }
            break;
        }

        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: {
            auto times_r = n00b_bstream_read_uleb128(stream);
            auto skip_r  = n00b_bstream_read_uleb128(stream);

            uint64_t times = 0;
            uint64_t skip  = 0;

            if (n00b_result_is_ok(times_r)) times = n00b_result_get(times_r);
            if (n00b_result_is_ok(skip_r))  skip  = n00b_result_get(skip_r);

            for (uint64_t j = 0;
                 j < times && bin->num_rebases < total; j++) {
                n00b_macho_rebase_t *rb = &bin->rebases[bin->num_rebases];
                rb->type          = rtype;
                rb->segment_index = seg_index;
                rb->address       = (seg_index < bin->num_segments)
                                  ? bin->segments[seg_index].vmaddr + seg_offset
                                  : 0;
                bin->num_rebases++;
                seg_offset += 8 + skip;
            }
            break;
        }

        default:
            break;
        }
    }

decode_done:
    (void)0;
}

// ============================================================================
// parse_exports — walk export trie
// ============================================================================

/// Recursive export trie walk.
static void
walk_export_trie(const uint8_t *trie_data, size_t trie_size,
                 size_t node_offset, char *prefix, size_t prefix_len,
                 n00b_macho_export_t *exports, uint32_t *count,
                 uint32_t max_exports, int depth)
{
    if (depth > 256 || node_offset >= trie_size || *count >= max_exports) {
        return;
    }

    const uint8_t *p   = trie_data + node_offset;
    const uint8_t *end = trie_data + trie_size;

    if (p >= end) {
        return;
    }

    // Terminal size (ULEB128).
    uint64_t terminal_size = 0;
    int      shift         = 0;

    while (p < end && (*p & 0x80)) {
        terminal_size |= (uint64_t)(*p & 0x7F) << shift;
        shift += 7;
        p++;
    }

    if (p < end) {
        terminal_size |= (uint64_t)(*p & 0x7F) << shift;
        p++;
    }

    if (terminal_size != 0 && *count < max_exports) {
        const uint8_t *terminal_start = p;

        // Read flags (ULEB128).
        uint64_t flags  = 0;

        shift = 0;

        while (p < end && (*p & 0x80)) {
            flags |= (uint64_t)(*p & 0x7F) << shift;
            shift += 7;
            p++;
        }

        if (p < end) {
            flags |= (uint64_t)(*p & 0x7F) << shift;
            p++;
        }

        n00b_macho_export_t *exp = &exports[*count];

        exp->name  = n00b_string_from_raw(prefix, (int64_t)prefix_len);
        exp->flags = flags;

        if (flags & EXPORT_SYMBOL_FLAGS_REEXPORT) {
            // ordinal (ULEB128)
            uint64_t ordinal = 0;

            shift = 0;

            while (p < end && (*p & 0x80)) {
                ordinal |= (uint64_t)(*p & 0x7F) << shift;
                shift += 7;
                p++;
            }

            if (p < end) {
                ordinal |= (uint64_t)(*p & 0x7F) << shift;
                p++;
            }

            exp->other = ordinal;

            // Import name (null-terminated string).
            if (p < end) {
                const char *import_start = (const char *)p;

                while (p < end && *p) {
                    p++;
                }

                if (p < end) {
                    size_t ilen = (size_t)((const char *)p - import_start);

                    exp->import_name = n00b_string_from_raw(import_start,
                                                            (int64_t)ilen);
                    p++; // skip NUL
                }
            }

            exp->address = 0;
        }
        else if (flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) {
            // stub offset + resolver offset
            uint64_t stub_off = 0;

            shift = 0;

            while (p < end && (*p & 0x80)) {
                stub_off |= (uint64_t)(*p & 0x7F) << shift;
                shift += 7;
                p++;
            }

            if (p < end) {
                stub_off |= (uint64_t)(*p & 0x7F) << shift;
                p++;
            }

            exp->address = stub_off;

            uint64_t resolver_off = 0;
            shift = 0;

            while (p < end && (*p & 0x80)) {
                resolver_off |= (uint64_t)(*p & 0x7F) << shift;
                shift += 7;
                p++;
            }

            if (p < end) {
                resolver_off |= (uint64_t)(*p & 0x7F) << shift;
                p++;
            }

            exp->other = resolver_off;
        }
        else {
            // Regular: address (ULEB128)
            uint64_t address = 0;

            shift = 0;

            while (p < end && (*p & 0x80)) {
                address |= (uint64_t)(*p & 0x7F) << shift;
                shift += 7;
                p++;
            }

            if (p < end) {
                address |= (uint64_t)(*p & 0x7F) << shift;
                p++;
            }

            exp->address = address;
        }

        (*count)++;

        // Skip to end of terminal data.
        p = terminal_start + terminal_size;
    }
    else if (terminal_size != 0) {
        p += terminal_size;
    }

    if (p >= end) {
        return;
    }

    // Number of children.
    uint8_t num_children = *p++;

    for (uint8_t i = 0; i < num_children && p < end; i++) {
        // Edge label (null-terminated string).
        const char *edge_start = (const char *)p;

        while (p < end && *p) {
            p++;
        }

        if (p >= end) {
            break;
        }

        size_t edge_len = (size_t)((const char *)p - edge_start);
        p++; // skip NUL

        // Child node offset (ULEB128).
        uint64_t child_offset = 0;
        shift = 0;

        while (p < end && (*p & 0x80)) {
            child_offset |= (uint64_t)(*p & 0x7F) << shift;
            shift += 7;
            p++;
        }

        if (p < end) {
            child_offset |= (uint64_t)(*p & 0x7F) << shift;
            p++;
        }

        // Build new prefix.
        size_t new_len = prefix_len + edge_len;

        if (new_len < 4096) {
            char new_prefix[4096];

            memcpy(new_prefix, prefix, prefix_len);
            memcpy(new_prefix + prefix_len, edge_start, edge_len);
            new_prefix[new_len] = '\0';

            walk_export_trie(trie_data, trie_size, (size_t)child_offset,
                             new_prefix, new_len,
                             exports, count, max_exports, depth + 1);
        }
    }
}

static void
parse_exports(n00b_bstream_t *stream, n00b_macho_binary_t *bin,
              uint32_t export_off, uint32_t export_size)
{
    if (export_size == 0 || export_off == 0) {
        return;
    }

    size_t actual_off = bin->fat_offset + export_off;

    auto trie_r = n00b_bstream_peek_bytes(stream, actual_off, export_size);

    if (n00b_result_is_err(trie_r)) {
        return;
    }

    n00b_buffer_t  *trie_buf  = n00b_result_get(trie_r);
    const uint8_t  *trie_data = (const uint8_t *)trie_buf->data;
    size_t          trie_size = n00b_buffer_len(trie_buf);

    // Generous upper bound.
    uint32_t max_exports = 65536;

    if (trie_size / 2 < max_exports) {
        max_exports = (uint32_t)(trie_size / 2);

        if (max_exports == 0) {
            max_exports = 1;
        }
    }

    n00b_macho_export_t *exports = n00b_alloc_array(n00b_macho_export_t,
                                                    max_exports);
    uint32_t count = 0;
    char     prefix[4096] = {};

    walk_export_trie(trie_data, trie_size, 0, prefix, 0,
                     exports, &count, max_exports, 0);

    if (count > 0) {
        bin->exports     = exports;
        bin->num_exports = count;
    }
}

// ============================================================================
// parse_chained_fixups — LC_DYLD_CHAINED_FIXUPS
// ============================================================================

/// Find the segment index containing a given file offset.
static int
segment_index_for_fileoff(n00b_macho_binary_t *bin, uint64_t fileoff)
{
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        uint64_t seg_start = bin->segments[i].fileoff;
        uint64_t seg_end   = seg_start + bin->segments[i].filesize;

        if (fileoff >= seg_start && fileoff < seg_end) {
            return (int)i;
        }
    }

    return -1;
}

static void
parse_chained_fixups(n00b_bstream_t *stream, n00b_macho_binary_t *bin,
                     uint32_t dataoff, uint32_t datasize)
{
    if (datasize == 0 || dataoff == 0) {
        return;
    }

    // Already have bindings from LC_DYLD_INFO? Skip.
    if (bin->num_bindings > 0 || bin->num_rebases > 0) {
        return;
    }

    size_t actual_off = bin->fat_offset + dataoff;

    auto r = n00b_bstream_peek_bytes(stream, actual_off, datasize);

    if (n00b_result_is_err(r)) {
        return;
    }

    n00b_buffer_t *fixup_data = n00b_result_get(r);
    const uint8_t *base = (const uint8_t *)fixup_data->data;
    size_t         len  = (size_t)n00b_buffer_len(fixup_data);

    if (len < sizeof(dyld_chained_fixups_header_t)) {
        return;
    }

    // Read the header.
    const dyld_chained_fixups_header_t *hdr =
        (const dyld_chained_fixups_header_t *)base;

    uint32_t starts_offset  = hdr->starts_offset;
    uint32_t imports_offset = hdr->imports_offset;
    uint32_t symbols_offset = hdr->symbols_offset;
    uint32_t imports_count  = hdr->imports_count;
    uint32_t imports_format = hdr->imports_format;

    // Sanity checks.
    if (starts_offset >= len || imports_offset >= len || symbols_offset >= len) {
        return;
    }

    // ---- Parse imports table ----
    const uint8_t *sym_base = base + symbols_offset;
    size_t sym_avail = len - symbols_offset;

    n00b_macho_chained_fixups_t *cf = n00b_alloc(n00b_macho_chained_fixups_t);
    cf->raw_data       = fixup_data;
    cf->imports_format = imports_format;
    cf->symbols_format = hdr->symbols_format;
    cf->num_imports    = imports_count;

    if (imports_count > 0 && imports_count < 1000000) {
        cf->imports = n00b_alloc_array(n00b_macho_chained_import_t, imports_count);

        for (uint32_t i = 0; i < imports_count; i++) {
            int32_t  lib_ordinal = 0;
            bool     weak        = false;
            uint32_t name_offset = 0;
            int64_t  addend      = 0;

            if (imports_format == DYLD_CHAINED_IMPORT) {
                size_t off = imports_offset + i * 4;

                if (off + 4 > len) break;

                uint32_t entry;
                memcpy(&entry, base + off, 4);

                lib_ordinal = (int32_t)(int8_t)(entry & 0xFF);
                weak        = (entry >> 8) & 1;
                name_offset = entry >> 9;
            }
            else if (imports_format == DYLD_CHAINED_IMPORT_ADDEND) {
                size_t off = imports_offset + i * 8;

                if (off + 8 > len) break;

                uint32_t entry;
                memcpy(&entry, base + off, 4);

                int32_t add;
                memcpy(&add, base + off + 4, 4);

                lib_ordinal = (int32_t)(int8_t)(entry & 0xFF);
                weak        = (entry >> 8) & 1;
                name_offset = entry >> 9;
                addend      = add;
            }
            else if (imports_format == DYLD_CHAINED_IMPORT_ADDEND64) {
                size_t off = imports_offset + i * 16;

                if (off + 16 > len) break;

                uint64_t entry;
                memcpy(&entry, base + off, 8);

                uint64_t add64;
                memcpy(&add64, base + off + 8, 8);

                lib_ordinal = (int32_t)(int16_t)(entry & 0xFFFF);
                weak        = (entry >> 16) & 1;
                name_offset = (uint32_t)(entry >> 32);
                addend      = (int64_t)add64;
            }
            else {
                break;
            }

            cf->imports[i].lib_ordinal = lib_ordinal;
            cf->imports[i].weak_import = weak;
            cf->imports[i].addend      = addend;

            if (name_offset < sym_avail) {
                size_t max_name = sym_avail - name_offset;
                size_t slen = strnlen((const char *)(sym_base + name_offset),
                                      max_name);
                cf->imports[i].symbol_name = n00b_string_from_raw(
                    (const char *)(sym_base + name_offset), (int64_t)slen);
            }
        }
    }

    bin->chained_fixups = cf;

    // ---- Walk segment starts and decode fixup chains ----
    // The starts table begins at starts_offset within the fixup data.
    const uint8_t *starts_base = base + starts_offset;
    size_t starts_avail = len - starts_offset;

    if (starts_avail < 4) return;

    uint32_t seg_count;
    memcpy(&seg_count, starts_base, 4);

    if (seg_count > 256 || 4 + seg_count * 4 > starts_avail) return;

    // Read per-segment offsets.
    uint32_t *seg_offsets = n00b_alloc_array(uint32_t, seg_count);

    for (uint32_t i = 0; i < seg_count; i++) {
        memcpy(&seg_offsets[i], starts_base + 4 + i * 4, 4);
    }

    // Estimate capacity for bindings + rebases.
    uint32_t bind_cap   = 1024;
    uint32_t rebase_cap = 1024;

    n00b_macho_binding_t *binds = n00b_alloc_array(n00b_macho_binding_t,
                                                    bind_cap);
    n00b_macho_rebase_t *rebases = n00b_alloc_array(n00b_macho_rebase_t,
                                                     rebase_cap);
    uint32_t bind_count   = 0;
    uint32_t rebase_count = 0;

    for (uint32_t seg_i = 0; seg_i < seg_count; seg_i++) {
        if (seg_offsets[seg_i] == 0) continue;

        size_t seg_starts_off = seg_offsets[seg_i];

        if (seg_starts_off + 22 > starts_avail) continue;

        const uint8_t *ss = starts_base + seg_starts_off;

        uint16_t page_size;
        uint16_t pointer_format;
        uint64_t segment_offset;
        uint16_t page_count;

        memcpy(&page_size, ss + 4, 2);
        memcpy(&pointer_format, ss + 6, 2);
        memcpy(&segment_offset, ss + 8, 8);
        // max_valid_pointer at ss + 16 (4 bytes) — skip
        memcpy(&page_count, ss + 20, 2);

        if (page_size == 0) continue;
        if (seg_starts_off + 22 + page_count * 2 > starts_avail) continue;

        // Determine stride (bytes per pointer for chain walking).
        uint32_t stride = 4;

        if (pointer_format == DYLD_CHAINED_PTR_64
         || pointer_format == DYLD_CHAINED_PTR_64_OFFSET
         || pointer_format == DYLD_CHAINED_PTR_ARM64E
         || pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND
         || pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND24
         || pointer_format == DYLD_CHAINED_PTR_ARM64E_KERNEL) {
            stride = 4;  // Chain delta is in units of 4 bytes for 64-bit.
        }
        else if (pointer_format == DYLD_CHAINED_PTR_32
              || pointer_format == DYLD_CHAINED_PTR_32_FIRMWARE) {
            stride = 4;
        }

        // Find the actual segment to compute virtual addresses.
        int actual_seg = segment_index_for_fileoff(bin, segment_offset);

        uint64_t seg_vmaddr = 0;

        if (actual_seg >= 0 && (uint32_t)actual_seg < bin->num_segments) {
            seg_vmaddr = bin->segments[actual_seg].vmaddr;
        }

        // Read segment content for chain walking.
        // Use the actual segment filesize if available, else page_count * page_size.
        size_t seg_read_size = (uint64_t)page_count * page_size;

        if (actual_seg >= 0 && (uint32_t)actual_seg < bin->num_segments) {
            uint64_t fs = bin->segments[actual_seg].filesize;
            if (fs > 0 && fs < seg_read_size) {
                seg_read_size = (size_t)fs;
            }
        }

        auto seg_r = n00b_bstream_peek_bytes(stream,
            bin->fat_offset + segment_offset,
            seg_read_size);

        if (n00b_result_is_err(seg_r)) continue;

        n00b_buffer_t *seg_buf = n00b_result_get(seg_r);
        const uint8_t *seg_data = (const uint8_t *)seg_buf->data;
        size_t seg_data_len = (size_t)n00b_buffer_len(seg_buf);

        for (uint16_t page_i = 0; page_i < page_count; page_i++) {
            uint16_t page_start;
            memcpy(&page_start, ss + 22 + page_i * 2, 2);

            if (page_start == DYLD_CHAINED_PTR_START_NONE) continue;

            // Walk the chain on this page.
            size_t page_off = (size_t)page_i * page_size;
            size_t chain_off = page_off + page_start;

            for (int iter = 0; iter < 100000; iter++) {
                if (chain_off + 8 > seg_data_len) break;

                uint64_t raw_val;
                memcpy(&raw_val, seg_data + chain_off, 8);

                uint64_t addr = seg_vmaddr + chain_off;
                uint32_t delta = 0;

                bool is_bind = false;
                uint32_t import_idx = 0;
                uint64_t target = 0;
                int64_t  fixup_addend = 0;

                if (pointer_format == DYLD_CHAINED_PTR_64
                 || pointer_format == DYLD_CHAINED_PTR_64_OFFSET) {
                    // Bit 63 = bind flag.
                    is_bind   = (raw_val >> 63) & 1;
                    delta     = (uint32_t)((raw_val >> 51) & 0xFFF);

                    if (is_bind) {
                        // Bits [0..23] = ordinal, [24..31] = addend.
                        import_idx = (uint32_t)(raw_val & 0xFFFFFF);
                        fixup_addend = (int64_t)(int8_t)((raw_val >> 24) & 0xFF);
                    }
                    else {
                        // Rebase: bits [0..35] = target.
                        target = raw_val & 0xFFFFFFFFFULL;

                        if (pointer_format == DYLD_CHAINED_PTR_64_OFFSET) {
                            target += bin->segments[0].vmaddr;
                        }
                    }
                }
                else if (pointer_format == DYLD_CHAINED_PTR_ARM64E
                      || pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND
                      || pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND24) {
                    // Bit 62 = bind flag.
                    is_bind = (raw_val >> 62) & 1;

                    if (is_bind) {
                        delta = (uint32_t)((raw_val >> 52) & 0x7FF);

                        if (pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND24) {
                            import_idx = (uint32_t)(raw_val & 0xFFFFFF);
                        }
                        else {
                            import_idx = (uint32_t)(raw_val & 0xFFFF);
                        }

                        fixup_addend = (int64_t)(int32_t)((raw_val >> 32) & 0x7FFFF);
                    }
                    else {
                        delta  = (uint32_t)((raw_val >> 52) & 0x7FF);
                        target = raw_val & 0x7FFFFFFFFULL;

                        if (pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND
                         || pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND24) {
                            target += bin->segments[0].vmaddr;
                        }
                    }
                }
                else if (pointer_format == DYLD_CHAINED_PTR_32) {
                    uint32_t raw32;
                    memcpy(&raw32, seg_data + chain_off, 4);

                    is_bind = (raw32 >> 31) & 1;
                    delta   = (raw32 >> 26) & 0x1F;

                    if (is_bind) {
                        import_idx   = raw32 & 0xFFFFF;
                        fixup_addend = 0;
                    }
                    else {
                        target = raw32 & 0x3FFFFFF;
                    }
                }
                else {
                    break;  // Unknown format.
                }

                if (is_bind) {
                    // Grow if needed.
                    if (bind_count >= bind_cap) {
                        uint32_t new_cap = bind_cap * 2;
                        n00b_macho_binding_t *new_arr =
                            n00b_alloc_array(n00b_macho_binding_t, new_cap);
                        memcpy(new_arr, binds,
                               bind_count * sizeof(n00b_macho_binding_t));
                        binds = new_arr;
                        bind_cap = new_cap;
                    }

                    n00b_macho_binding_t *b = &binds[bind_count];
                    b->type            = 1;  // BIND_TYPE_POINTER
                    b->address         = addr;
                    b->addend          = fixup_addend;
                    b->segment_index   = (actual_seg >= 0) ? (uint8_t)actual_seg : 0;
                    b->is_weak         = false;
                    b->is_lazy         = false;

                    if (import_idx < imports_count) {
                        b->symbol_name     = cf->imports[import_idx].symbol_name;
                        b->library_ordinal = cf->imports[import_idx].lib_ordinal;
                        b->is_weak         = cf->imports[import_idx].weak_import;
                        b->addend         += cf->imports[import_idx].addend;
                    }

                    bind_count++;
                }
                else {
                    // Grow if needed.
                    if (rebase_count >= rebase_cap) {
                        uint32_t new_cap = rebase_cap * 2;
                        n00b_macho_rebase_t *new_arr =
                            n00b_alloc_array(n00b_macho_rebase_t, new_cap);
                        memcpy(new_arr, rebases,
                               rebase_count * sizeof(n00b_macho_rebase_t));
                        rebases = new_arr;
                        rebase_cap = new_cap;
                    }

                    n00b_macho_rebase_t *rb = &rebases[rebase_count];
                    rb->type          = REBASE_TYPE_POINTER;
                    rb->segment_index = (actual_seg >= 0) ? (uint8_t)actual_seg : 0;
                    rb->address       = addr;
                    rebase_count++;
                }

                if (delta == 0) break;

                chain_off += (size_t)delta * stride;
            }
        }
    }

    if (bind_count > 0) {
        bin->bindings     = binds;
        bin->num_bindings = bind_count;
    }

    if (rebase_count > 0) {
        bin->rebases     = rebases;
        bin->num_rebases = rebase_count;
    }
}

// ============================================================================
// parse_function_starts
// ============================================================================

static void
parse_function_starts(n00b_bstream_t *stream, n00b_macho_binary_t *bin,
                      uint32_t dataoff, uint32_t datasize)
{
    if (datasize == 0 || dataoff == 0) {
        return;
    }

    size_t actual_off = bin->fat_offset + dataoff;

    auto data_r = n00b_bstream_peek_bytes(stream, actual_off, datasize);

    if (n00b_result_is_err(data_r)) {
        return;
    }

    n00b_buffer_t *data = n00b_result_get(data_r);

    // Find __TEXT segment vmaddr as base.
    uint64_t text_addr = 0;

    for (uint32_t i = 0; i < bin->num_segments; i++) {
        if (strcmp(bin->segments[i].name, "__TEXT") == 0) {
            text_addr = bin->segments[i].vmaddr;
            break;
        }
    }

    // First pass: count ULEB128 deltas.
    uint32_t       count = 0;
    const uint8_t *p     = (const uint8_t *)data->data;
    const uint8_t *end   = p + n00b_buffer_len(data);

    while (p < end) {
        if (*p == 0) {
            break;
        }

        // Skip ULEB128.
        while (p < end && (*p & 0x80)) {
            p++;
        }

        if (p < end) {
            p++;
        }

        count++;
    }

    if (count == 0) {
        return;
    }

    n00b_macho_function_starts_t *fs = n00b_alloc(n00b_macho_function_starts_t);

    fs->addresses = n00b_alloc_array(uint64_t, count);
    fs->count     = 0;

    // Second pass: decode.
    p = (const uint8_t *)data->data;

    uint64_t addr = text_addr;

    while (p < end && fs->count < count) {
        if (*p == 0) {
            break;
        }

        uint64_t delta = 0;
        int      shift = 0;

        while (p < end && (*p & 0x80)) {
            delta |= (uint64_t)(*p & 0x7F) << shift;
            shift += 7;
            p++;
        }

        if (p < end) {
            delta |= (uint64_t)(*p & 0x7F) << shift;
            p++;
        }

        addr += delta;
        fs->addresses[fs->count] = addr;
        fs->count++;
    }

    bin->function_starts = fs;
}

// ============================================================================
// parse_code_signature
// ============================================================================

static void
parse_code_signature(n00b_bstream_t *stream, n00b_macho_binary_t *bin,
                     uint32_t dataoff, uint32_t datasize)
{
    if (datasize == 0 || dataoff == 0) {
        return;
    }

    size_t actual_off = bin->fat_offset + dataoff;

    auto r = n00b_bstream_peek_bytes(stream, actual_off, datasize);

    if (n00b_result_is_err(r)) {
        return;
    }

    n00b_macho_code_signature_t *cs = n00b_alloc(n00b_macho_code_signature_t);

    cs->dataoff  = dataoff;
    cs->datasize = datasize;
    cs->data     = n00b_result_get(r);

    bin->code_signature = cs;

    // Parse the SuperBlob structure for detailed code signature info.
    const uint8_t *base = (const uint8_t *)cs->data->data;
    size_t         len  = (size_t)n00b_buffer_len(cs->data);

    if (len < 12) return;

    uint32_t sb_magic = cs_be32(base);
    uint32_t sb_len   = cs_be32(base + 4);
    uint32_t sb_count = cs_be32(base + 8);

    if (sb_magic != CSMAGIC_EMBEDDED_SIGNATURE || sb_len > len) return;
    if (sb_count > 1000) return; // sanity

    n00b_macho_code_signature_parsed_t *csp = n00b_alloc(
        n00b_macho_code_signature_parsed_t);

    csp->blobs = n00b_alloc_array(n00b_macho_cs_blob_t, sb_count);
    csp->num_blobs = sb_count;

    for (uint32_t i = 0; i < sb_count; i++) {
        size_t idx_off = 12 + i * 8;

        if (idx_off + 8 > len) break;

        uint32_t slot_type   = cs_be32(base + idx_off);
        uint32_t slot_offset = cs_be32(base + idx_off + 4);

        csp->blobs[i].type   = slot_type;
        csp->blobs[i].offset = slot_offset;

        if (slot_offset + 8 > len) continue;

        uint32_t blob_magic = cs_be32(base + slot_offset);
        uint32_t blob_len   = cs_be32(base + slot_offset + 4);

        if (slot_offset + blob_len > len) continue;

        csp->blobs[i].data = n00b_buffer_from_bytes(
            (char *)(base + slot_offset), blob_len);

        if (blob_magic == CSMAGIC_CODEDIRECTORY && blob_len >= 44) {
            const uint8_t *cd = base + slot_offset;
            n00b_macho_cs_code_directory_t *cdir = n00b_alloc(
                n00b_macho_cs_code_directory_t);

            cdir->version        = cs_be32(cd + 8);
            cdir->flags          = cs_be32(cd + 12);
            uint32_t ident_off   = cs_be32(cd + 20);
            cdir->n_special_slots = cs_be32(cd + 24);
            cdir->n_code_slots    = cs_be32(cd + 28);
            cdir->code_limit      = cs_be32(cd + 32);
            cdir->hash_size       = cd[36];
            cdir->hash_type       = cd[37];
            // cd[38] = platform, cd[39] = page_size_log2
            cdir->page_size       = 1u << cd[39];

            if (ident_off > 0 && ident_off < blob_len) {
                size_t max_ident = blob_len - ident_off;
                size_t ident_len = strnlen(
                    (const char *)(cd + ident_off), max_ident);
                cdir->identifier = n00b_string_from_raw(
                    (const char *)(cd + ident_off), (int64_t)ident_len);
            }

            // Team ID is at offset 40 in version >= 0x20200.
            if (cdir->version >= 0x20200 && blob_len >= 48) {
                uint32_t team_off = cs_be32(cd + 40);

                if (team_off > 0 && team_off < blob_len) {
                    size_t max_team = blob_len - team_off;
                    size_t team_len = strnlen(
                        (const char *)(cd + team_off), max_team);
                    cdir->team_id = n00b_string_from_raw(
                        (const char *)(cd + team_off), (int64_t)team_len);
                }
            }

            csp->code_directory = cdir;
        }
        else if (blob_magic == CSMAGIC_EMBEDDED_ENTITLEMENTS && blob_len > 8) {
            size_t xml_len = blob_len - 8;
            csp->entitlements_xml = n00b_string_from_raw(
                (const char *)(base + slot_offset + 8), (int64_t)xml_len);
        }
        else if (blob_magic == CSMAGIC_REQUIREMENTS) {
            csp->requirements = n00b_buffer_from_bytes(
                (char *)(base + slot_offset), blob_len);
        }
        else if (blob_magic == CSMAGIC_BLOBWRAPPER && slot_type == CSSLOT_SIGNATURESLOT) {
            csp->cms_signature = n00b_buffer_from_bytes(
                (char *)(base + slot_offset), blob_len);
        }
    }

    bin->code_signature_parsed = csp;
}

// ============================================================================
// parse_load_commands
// ============================================================================

static void
parse_load_commands(n00b_bstream_t *stream, n00b_macho_binary_t *bin)
{
    uint32_t ncmds = bin->header.ncmds;

    if (ncmds == 0) {
        return;
    }

    // Sanity: reject absurd ncmds to prevent huge allocations.
    if (ncmds > 10000) {
        ncmds = 10000;
    }

    bin->commands     = n00b_alloc_array(n00b_macho_command_t, ncmds);
    bin->num_commands = ncmds;

    // Deferred parsing state.
    uint32_t symtab_symoff  = 0;
    uint32_t symtab_nsyms   = 0;
    uint32_t symtab_stroff  = 0;
    uint32_t symtab_strsize = 0;

    uint32_t dysymtab_indirectsymoff = 0;
    uint32_t dysymtab_nindirectsyms  = 0;

    uint32_t dyld_rebase_off  = 0, dyld_rebase_size  = 0;
    uint32_t dyld_bind_off    = 0, dyld_bind_size    = 0;
    uint32_t dyld_weak_off    = 0, dyld_weak_size    = 0;
    uint32_t dyld_lazy_off    = 0, dyld_lazy_size    = 0;
    uint32_t dyld_export_off  = 0, dyld_export_size  = 0;

    uint32_t func_starts_off  = 0, func_starts_size  = 0;
    uint32_t code_sig_off     = 0, code_sig_size     = 0;
    uint32_t chained_off      = 0, chained_size      = 0;
    uint32_t exports_trie_off = 0, exports_trie_size = 0;

    // Dylib collection — growable.
    uint32_t dylib_cap = 16;

    bin->dylibs     = n00b_alloc_array(n00b_macho_dylib_t, dylib_cap);
    bin->num_dylibs = 0;

    // Header is 32 bytes for 64-bit Mach-O.
    size_t cmd_pos = bin->fat_offset + sizeof(n00b_macho_header64_t);

    for (uint32_t i = 0; i < ncmds; i++) {
        size_t cmd_start = cmd_pos;

        n00b_bstream_setpos(stream, cmd_start);

        auto cmd_r     = n00b_bstream_read_u32(stream);
        auto cmdsize_r = n00b_bstream_read_u32(stream);

        if (n00b_result_is_err(cmd_r) || n00b_result_is_err(cmdsize_r)) {
            break;
        }

        uint32_t cmd     = n00b_result_get(cmd_r);
        uint32_t cmdsize = n00b_result_get(cmdsize_r);

        // Sanity: cmdsize must be at least 8 (cmd + cmdsize fields) and
        // must not extend past the load commands region.
        if (cmdsize < 8) {
            break;
        }

        bin->commands[i].cmd     = cmd;
        bin->commands[i].cmdsize = cmdsize;

        // Slice-relative on-disk offset of this command (D-019). cmd_start
        // includes fat_offset; subtract it so the value is relative to the
        // slice start (== N00B_MACHO_HEADER_64_SIZE + Σ prior cmdsize).
        bin->commands[i].file_offset = (uint64_t)cmd_start - bin->fat_offset;

        // Store raw command data.
        if (cmdsize > 0) {
            auto raw_r = n00b_bstream_peek_bytes(stream, cmd_start, cmdsize);

            if (n00b_result_is_ok(raw_r)) {
                bin->commands[i].raw_data = n00b_result_get(raw_r);
            }
        }

        // Dispatch by command type.
        // Stream is currently at cmd_start + 8.
        switch (cmd) {
        case LC_SEGMENT_64:
            parse_segment(stream, bin, cmd_start, cmdsize);
            break;

        case LC_SYMTAB: {
            auto so_r  = n00b_bstream_read_u32(stream);
            auto ns_r  = n00b_bstream_read_u32(stream);
            auto str_r = n00b_bstream_read_u32(stream);
            auto ss_r  = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(so_r))  symtab_symoff  = n00b_result_get(so_r);
            if (n00b_result_is_ok(ns_r))  symtab_nsyms   = n00b_result_get(ns_r);
            if (n00b_result_is_ok(str_r)) symtab_stroff  = n00b_result_get(str_r);
            if (n00b_result_is_ok(ss_r))  symtab_strsize = n00b_result_get(ss_r);
            break;
        }

        case LC_DYSYMTAB: {
            // Skip to indirectsymoff (offset 56 from cmd start, or 48 from
            // current position which is cmd_start+8).
            n00b_bstream_setpos(stream, cmd_start + 56);

            auto iso_r = n00b_bstream_read_u32(stream);
            auto nis_r = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(iso_r)) {
                dysymtab_indirectsymoff = n00b_result_get(iso_r);
            }
            if (n00b_result_is_ok(nis_r)) {
                dysymtab_nindirectsyms = n00b_result_get(nis_r);
            }
            break;
        }

        case LC_LOAD_DYLIB:
        case LC_LOAD_WEAK_DYLIB:
        case LC_REEXPORT_DYLIB:
        case LC_LAZY_LOAD_DYLIB:
        case LC_LOAD_UPWARD_DYLIB:
        case LC_ID_DYLIB: {
            auto name_off_r = n00b_bstream_read_u32(stream);
            auto ts_r       = n00b_bstream_read_u32(stream);
            auto cv_r       = n00b_bstream_read_u32(stream);
            auto compat_r   = n00b_bstream_read_u32(stream);

            if (bin->num_dylibs >= dylib_cap) {
                dylib_cap *= 2;

                n00b_macho_dylib_t *new_dylibs
                    = n00b_alloc_array(n00b_macho_dylib_t, dylib_cap);

                memcpy(new_dylibs, bin->dylibs,
                       bin->num_dylibs * sizeof(n00b_macho_dylib_t));
                bin->dylibs = new_dylibs;
            }

            n00b_macho_dylib_t *dl = &bin->dylibs[bin->num_dylibs];

            dl->cmd = cmd;

            if (n00b_result_is_ok(name_off_r)) {
                dl->name = read_lc_string(stream, cmd_start,
                                          cmdsize,
                                          n00b_result_get(name_off_r));
            }

            if (n00b_result_is_ok(ts_r))    dl->timestamp       = n00b_result_get(ts_r);
            if (n00b_result_is_ok(cv_r))    dl->current_version  = n00b_result_get(cv_r);
            if (n00b_result_is_ok(compat_r)) dl->compat_version  = n00b_result_get(compat_r);

            bin->num_dylibs++;
            break;
        }

        case LC_LOAD_DYLINKER:
        case LC_ID_DYLINKER: {
            auto name_off_r = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(name_off_r)) {
                bin->dylinker = read_lc_string(stream, cmd_start,
                                               cmdsize,
                                               n00b_result_get(name_off_r));
            }
            break;
        }

        case LC_UUID: {
            auto uuid_r = n00b_bstream_read_bytes(stream, 16);

            if (n00b_result_is_ok(uuid_r)) {
                n00b_buffer_t *ub = n00b_result_get(uuid_r);

                memcpy(bin->uuid, ub->data, 16);
            }
            break;
        }

        case LC_THREAD:
        case LC_UNIXTHREAD: {
            // Thread state: flavor(u32), count(u32), state(count * u32).
            // Extract entrypoint only if LC_MAIN wasn't already seen.
            if (bin->entrypoint == 0 && cmdsize > 16) {
                auto flavor_r = n00b_bstream_read_u32(stream);
                auto count_r  = n00b_bstream_read_u32(stream);

                if (n00b_result_is_ok(flavor_r)
                    && n00b_result_is_ok(count_r)) {
                    uint32_t flavor = n00b_result_get(flavor_r);
                    uint32_t count  = n00b_result_get(count_r);
                    (void)flavor;

                    // x86_64 thread state: RIP is at word offset 16.
                    // ARM64 thread state: PC is at word offset 32.
                    // Read as u64 at the appropriate byte offset.
                    uint32_t rip_word_off = 16;  // x86_64 default

                    if (bin->header.cputype == CPU_TYPE_ARM64) {
                        rip_word_off = 32;
                    }

                    if (count > rip_word_off + 1) {
                        size_t state_start = n00b_bstream_pos(stream);
                        n00b_bstream_setpos(stream,
                            state_start + (size_t)rip_word_off * 4);

                        auto pc_r = n00b_bstream_read_u64(stream);

                        if (n00b_result_is_ok(pc_r)) {
                            bin->entrypoint = n00b_result_get(pc_r);
                        }
                    }
                }
            }
            break;
        }

        case LC_MAIN: {
            auto entryoff_r  = n00b_bstream_read_u64(stream);
            auto stacksize_r = n00b_bstream_read_u64(stream);

            if (n00b_result_is_ok(entryoff_r)) {
                bin->entrypoint = n00b_result_get(entryoff_r);
            }

            if (n00b_result_is_ok(stacksize_r)) {
                bin->stack_size = n00b_result_get(stacksize_r);
            }
            break;
        }

        case LC_DYLD_INFO:
        case LC_DYLD_INFO_ONLY: {
            auto ro_r = n00b_bstream_read_u32(stream);
            auto rs_r = n00b_bstream_read_u32(stream);
            auto bo_r = n00b_bstream_read_u32(stream);
            auto bs_r = n00b_bstream_read_u32(stream);
            auto wo_r = n00b_bstream_read_u32(stream);
            auto ws_r = n00b_bstream_read_u32(stream);
            auto lo_r = n00b_bstream_read_u32(stream);
            auto ls_r = n00b_bstream_read_u32(stream);
            auto eo_r = n00b_bstream_read_u32(stream);
            auto es_r = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(ro_r)) dyld_rebase_off  = n00b_result_get(ro_r);
            if (n00b_result_is_ok(rs_r)) dyld_rebase_size  = n00b_result_get(rs_r);
            if (n00b_result_is_ok(bo_r)) dyld_bind_off    = n00b_result_get(bo_r);
            if (n00b_result_is_ok(bs_r)) dyld_bind_size    = n00b_result_get(bs_r);
            if (n00b_result_is_ok(wo_r)) dyld_weak_off    = n00b_result_get(wo_r);
            if (n00b_result_is_ok(ws_r)) dyld_weak_size    = n00b_result_get(ws_r);
            if (n00b_result_is_ok(lo_r)) dyld_lazy_off    = n00b_result_get(lo_r);
            if (n00b_result_is_ok(ls_r)) dyld_lazy_size    = n00b_result_get(ls_r);
            if (n00b_result_is_ok(eo_r)) dyld_export_off  = n00b_result_get(eo_r);
            if (n00b_result_is_ok(es_r)) dyld_export_size  = n00b_result_get(es_r);
            break;
        }

        case LC_FUNCTION_STARTS: {
            auto fo_r = n00b_bstream_read_u32(stream);
            auto fs_r = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(fo_r)) func_starts_off  = n00b_result_get(fo_r);
            if (n00b_result_is_ok(fs_r)) func_starts_size = n00b_result_get(fs_r);
            break;
        }

        case LC_CODE_SIGNATURE: {
            auto co_r = n00b_bstream_read_u32(stream);
            auto cs_r = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(co_r)) code_sig_off  = n00b_result_get(co_r);
            if (n00b_result_is_ok(cs_r)) code_sig_size = n00b_result_get(cs_r);
            break;
        }

        case LC_SOURCE_VERSION: {
            auto sv_r = n00b_bstream_read_u64(stream);

            if (n00b_result_is_ok(sv_r)) {
                bin->source_version = n00b_result_get(sv_r);
            }
            break;
        }

        case LC_BUILD_VERSION: {
            auto plat_r   = n00b_bstream_read_u32(stream);
            auto minos_r  = n00b_bstream_read_u32(stream);
            auto sdk_r    = n00b_bstream_read_u32(stream);
            auto ntools_r = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(plat_r) && n00b_result_is_ok(ntools_r)) {
                n00b_macho_build_version_t *bv = n00b_alloc(
                    n00b_macho_build_version_t);

                bv->platform  = n00b_result_get(plat_r);
                bv->minos     = n00b_result_is_ok(minos_r)
                    ? n00b_result_get(minos_r) : 0;
                bv->sdk       = n00b_result_is_ok(sdk_r)
                    ? n00b_result_get(sdk_r) : 0;
                bv->num_tools = n00b_result_get(ntools_r);

                if (bv->num_tools > 0 && bv->num_tools < 256) {
                    bv->tools = n00b_alloc_array(n00b_macho_build_tool_t,
                                                  bv->num_tools);

                    for (uint32_t t = 0; t < bv->num_tools; t++) {
                        auto tool_r = n00b_bstream_read_u32(stream);
                        auto ver_r  = n00b_bstream_read_u32(stream);

                        if (n00b_result_is_ok(tool_r)) {
                            bv->tools[t].tool = n00b_result_get(tool_r);
                        }

                        if (n00b_result_is_ok(ver_r)) {
                            bv->tools[t].version = n00b_result_get(ver_r);
                        }
                    }
                }

                bin->build_version = bv;
            }
            break;
        }

        case LC_RPATH: {
            auto path_off_r = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(path_off_r)) {
                n00b_string_t *path = read_lc_string(
                    stream, cmd_start, cmdsize,
                    n00b_result_get(path_off_r));

                if (path && path->data && path->u8_bytes > 0) {
                    uint32_t old_count = bin->num_rpaths;
                    uint32_t new_count = old_count + 1;
                    n00b_string_t **new_arr = n00b_alloc_array(
                        n00b_string_t *, new_count);

                    if (old_count > 0) {
                        memcpy(new_arr, bin->rpaths,
                               old_count * sizeof(n00b_string_t *));
                    }

                    new_arr[old_count] = path;
                    bin->rpaths       = new_arr;
                    bin->num_rpaths   = new_count;
                }
            }
            break;
        }

        case LC_VERSION_MIN_MACOSX:
        case LC_VERSION_MIN_IPHONEOS:
        case LC_VERSION_MIN_TVOS:
        case LC_VERSION_MIN_WATCHOS: {
            auto ver_r = n00b_bstream_read_u32(stream);
            auto sdk_r = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(ver_r)) {
                n00b_macho_version_min_t *vm = n00b_alloc(
                    n00b_macho_version_min_t);

                vm->cmd     = cmd;
                vm->version = n00b_result_get(ver_r);
                vm->sdk     = n00b_result_is_ok(sdk_r)
                    ? n00b_result_get(sdk_r) : 0;

                bin->version_min = vm;
            }
            break;
        }

        case LC_LINKER_OPTION: {
            auto count_r = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(count_r)) {
                uint32_t str_count = n00b_result_get(count_r);

                if (str_count > 0 && str_count < 1024) {
                    n00b_string_t **strings = n00b_alloc_array(
                        n00b_string_t *, str_count);

                    for (uint32_t s = 0; s < str_count; s++) {
                        auto sr = n00b_bstream_read_cstring(stream);

                        if (n00b_result_is_ok(sr)) {
                            strings[s] = n00b_result_get(sr);
                        }
                    }

                    uint32_t old_count = bin->num_linker_options;
                    uint32_t new_count = old_count + 1;
                    n00b_macho_linker_option_t *new_arr = n00b_alloc_array(
                        n00b_macho_linker_option_t, new_count);

                    if (old_count > 0) {
                        memcpy(new_arr, bin->linker_options,
                               old_count * sizeof(n00b_macho_linker_option_t));
                    }

                    new_arr[old_count].strings = strings;
                    new_arr[old_count].count   = str_count;
                    bin->linker_options     = new_arr;
                    bin->num_linker_options = new_count;
                }
            }
            break;
        }

        case LC_DATA_IN_CODE: {
            auto do_r = n00b_bstream_read_u32(stream);
            auto ds_r = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(do_r) && n00b_result_is_ok(ds_r)) {
                uint32_t dataoff  = n00b_result_get(do_r);
                uint32_t datasize = n00b_result_get(ds_r);
                uint32_t nentries = datasize / 8;

                // Retain the on-disk __LINKEDIT extent (D-019), even when
                // there are zero entries.
                if (datasize != 0) {
                    bin->data_in_code_region.file_offset = dataoff;
                    bin->data_in_code_region.size        = datasize;
                }

                if (nentries > 0) {
                    n00b_macho_data_in_code_t *dic = n00b_alloc(
                        n00b_macho_data_in_code_t);

                    dic->entries = n00b_alloc_array(
                        n00b_macho_data_in_code_entry_t, nentries);
                    dic->count = nentries;

                    size_t saved = n00b_bstream_pos(stream);
                    n00b_bstream_setpos(stream, bin->fat_offset + dataoff);

                    for (uint32_t e = 0; e < nentries; e++) {
                        auto eo_r = n00b_bstream_read_u32(stream);
                        auto el_r = n00b_bstream_read_u16(stream);
                        auto ek_r = n00b_bstream_read_u16(stream);

                        if (n00b_result_is_ok(eo_r)) {
                            dic->entries[e].offset = n00b_result_get(eo_r);
                        }

                        if (n00b_result_is_ok(el_r)) {
                            dic->entries[e].length = n00b_result_get(el_r);
                        }

                        if (n00b_result_is_ok(ek_r)) {
                            dic->entries[e].kind = n00b_result_get(ek_r);
                        }
                    }

                    n00b_bstream_setpos(stream, saved);
                    bin->data_in_code = dic;
                }
            }
            break;
        }

        case LC_ENCRYPTION_INFO_64: {
            auto co_r = n00b_bstream_read_u32(stream);
            auto cs_r = n00b_bstream_read_u32(stream);
            auto ci_r = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(co_r)) {
                n00b_macho_encryption_info_t *ei = n00b_alloc(
                    n00b_macho_encryption_info_t);

                ei->cryptoff  = n00b_result_get(co_r);
                ei->cryptsize = n00b_result_is_ok(cs_r)
                    ? n00b_result_get(cs_r) : 0;
                ei->cryptid   = n00b_result_is_ok(ci_r)
                    ? n00b_result_get(ci_r) : 0;

                bin->encryption_info = ei;
            }
            break;
        }

        case LC_FILESET_ENTRY: {
            auto vmaddr_r  = n00b_bstream_read_u64(stream);
            auto fileoff_r = n00b_bstream_read_u64(stream);
            auto eid_off_r = n00b_bstream_read_u32(stream);
            auto rsv_r     = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(vmaddr_r) && n00b_result_is_ok(fileoff_r)) {
                n00b_string_t *entry_id = n00b_string_empty();

                if (n00b_result_is_ok(eid_off_r)) {
                    entry_id = read_lc_string(
                        stream, cmd_start, cmdsize,
                        n00b_result_get(eid_off_r));
                }

                uint32_t old_count = bin->num_fileset_entries;
                uint32_t new_count = old_count + 1;
                n00b_macho_fileset_entry_t *new_arr = n00b_alloc_array(
                    n00b_macho_fileset_entry_t, new_count);

                if (old_count > 0) {
                    memcpy(new_arr, bin->fileset_entries,
                           old_count * sizeof(n00b_macho_fileset_entry_t));
                }

                new_arr[old_count].vmaddr   = n00b_result_get(vmaddr_r);
                new_arr[old_count].fileoff  = n00b_result_get(fileoff_r);
                new_arr[old_count].entry_id = entry_id;
                new_arr[old_count].reserved = n00b_result_is_ok(rsv_r)
                    ? n00b_result_get(rsv_r) : 0;

                bin->fileset_entries     = new_arr;
                bin->num_fileset_entries = new_count;
            }
            break;
        }

        case LC_DYLD_CHAINED_FIXUPS: {
            auto co_r = n00b_bstream_read_u32(stream);
            auto cs_r = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(co_r)) chained_off  = n00b_result_get(co_r);
            if (n00b_result_is_ok(cs_r)) chained_size = n00b_result_get(cs_r);
            break;
        }

        case LC_DYLD_EXPORTS_TRIE: {
            auto eo_r = n00b_bstream_read_u32(stream);
            auto es_r = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(eo_r)) exports_trie_off  = n00b_result_get(eo_r);
            if (n00b_result_is_ok(es_r)) exports_trie_size = n00b_result_get(es_r);
            break;
        }

        default:
            // Unknown command — raw_data already stored.
            break;
        }

        cmd_pos = cmd_start + cmdsize;
    }

    // Retain the decoded __LINKEDIT sub-region offsets/sizes (D-019). These
    // are slice-relative on-disk offsets (the parser adds bin->fat_offset
    // when seeking to them); sizes are derived from the decoded counts.
    // Each region stays {0,0} when its load command is absent.
    if (symtab_nsyms != 0) {
        bin->symtab_nlist.file_offset = symtab_symoff;
        bin->symtab_nlist.size        = (uint64_t)symtab_nsyms
                                      * sizeof(n00b_macho_nlist64_t);
    }
    if (symtab_strsize != 0) {
        bin->symtab_strings.file_offset = symtab_stroff;
        bin->symtab_strings.size        = symtab_strsize;
    }
    if (dysymtab_nindirectsyms != 0) {
        bin->indirect_symtab.file_offset = dysymtab_indirectsymoff;
        bin->indirect_symtab.size        = (uint64_t)dysymtab_nindirectsyms
                                         * sizeof(uint32_t);
    }
    // LC_DYLD_INFO spans rebase..export; its on-disk extent is the union of
    // the sub-blobs, which are laid out contiguously from the first offset.
    if (dyld_rebase_off != 0 || dyld_bind_off != 0 || dyld_weak_off != 0
        || dyld_lazy_off != 0 || dyld_export_off != 0) {
        uint32_t di_start = UINT32_MAX;
        uint32_t di_end   = 0;

        if (dyld_rebase_off != 0) {
            if (dyld_rebase_off < di_start) di_start = dyld_rebase_off;
            if (dyld_rebase_off + dyld_rebase_size > di_end)
                di_end = dyld_rebase_off + dyld_rebase_size;
        }
        if (dyld_bind_off != 0) {
            if (dyld_bind_off < di_start) di_start = dyld_bind_off;
            if (dyld_bind_off + dyld_bind_size > di_end)
                di_end = dyld_bind_off + dyld_bind_size;
        }
        if (dyld_weak_off != 0) {
            if (dyld_weak_off < di_start) di_start = dyld_weak_off;
            if (dyld_weak_off + dyld_weak_size > di_end)
                di_end = dyld_weak_off + dyld_weak_size;
        }
        if (dyld_lazy_off != 0) {
            if (dyld_lazy_off < di_start) di_start = dyld_lazy_off;
            if (dyld_lazy_off + dyld_lazy_size > di_end)
                di_end = dyld_lazy_off + dyld_lazy_size;
        }
        if (dyld_export_off != 0) {
            if (dyld_export_off < di_start) di_start = dyld_export_off;
            if (dyld_export_off + dyld_export_size > di_end)
                di_end = dyld_export_off + dyld_export_size;
        }

        if (di_start != UINT32_MAX && di_end > di_start) {
            bin->dyld_info.file_offset = di_start;
            bin->dyld_info.size        = (uint64_t)di_end - di_start;
        }
    }
    if (func_starts_size != 0) {
        bin->function_starts_region.file_offset = func_starts_off;
        bin->function_starts_region.size        = func_starts_size;
    }
    if (chained_size != 0) {
        bin->chained_fixups_region.file_offset = chained_off;
        bin->chained_fixups_region.size        = chained_size;
    }
    // data_in_code_region is populated inside the LC_DATA_IN_CODE switch case
    // above (from that case's dataoff/datasize locals); no retained loop-scope
    // parse-local is needed here.

    // Post-processing: parse symbols.
    parse_symbols(stream, bin, symtab_symoff, symtab_nsyms,
                  symtab_stroff, symtab_strsize);

    // Parse indirect symbols.
    parse_indirect_symbols(stream, bin,
                           dysymtab_indirectsymoff, dysymtab_nindirectsyms);

    // Parse relocations.
    parse_relocations(stream, bin);

    // Parse dyld info: rebases, bindings, exports.
    parse_rebases(stream, bin, dyld_rebase_off, dyld_rebase_size);

    // Bindings: estimate capacity from opcode stream sizes, then grow if needed.
    // Each binding is at least 2 bytes of opcodes, so size/2 is a safe upper bound.
    uint32_t bind_cap = (dyld_bind_size + dyld_weak_size + dyld_lazy_size) / 2;

    if (bind_cap < 64) bind_cap = 64;
    if (bind_cap > 1000000) bind_cap = 1000000;

    n00b_macho_binding_t *bind_buf = n00b_alloc_array(n00b_macho_binding_t,
                                                      bind_cap);
    uint32_t bind_total = 0;

    bind_total += decode_bindings(stream, bin,
                                 dyld_bind_off, dyld_bind_size,
                                 bind_buf + bind_total,
                                 bind_cap - bind_total,
                                 false, false);

    bind_total += decode_bindings(stream, bin,
                                 dyld_weak_off, dyld_weak_size,
                                 bind_buf + bind_total,
                                 bind_cap - bind_total,
                                 true, false);

    bind_total += decode_bindings(stream, bin,
                                 dyld_lazy_off, dyld_lazy_size,
                                 bind_buf + bind_total,
                                 bind_cap - bind_total,
                                 false, true);

    if (bind_total > 0) {
        bin->bindings     = bind_buf;
        bin->num_bindings = bind_total;
    }

    // Parse exports (prefer LC_DYLD_INFO, fall back to LC_DYLD_EXPORTS_TRIE).
    if (dyld_export_off != 0 && dyld_export_size != 0) {
        parse_exports(stream, bin, dyld_export_off, dyld_export_size);
    }
    else if (exports_trie_off != 0 && exports_trie_size != 0) {
        parse_exports(stream, bin, exports_trie_off, exports_trie_size);
    }

    // Parse chained fixups (modern binding/rebase format).
    parse_chained_fixups(stream, bin, chained_off, chained_size);

    // Parse function starts.
    parse_function_starts(stream, bin, func_starts_off, func_starts_size);

    // Parse code signature.
    parse_code_signature(stream, bin, code_sig_off, code_sig_size);
}

// ============================================================================
// n00b_macho_parse_single
// ============================================================================

n00b_result_t(n00b_macho_binary_t *)
n00b_macho_parse_single(n00b_bstream_t *stream)
{
    if (!stream) {
        return n00b_result_err(n00b_macho_binary_t *, N00B_ERR_READ);
    }

    n00b_macho_binary_t *bin = n00b_alloc(n00b_macho_binary_t);

    bin->stream     = stream;
    bin->fat_offset = n00b_bstream_pos(stream);

    // 1. Parse header.
    auto hdr_r = parse_header(stream, bin);

    if (n00b_result_is_err(hdr_r)) {
        return n00b_result_err(n00b_macho_binary_t *,
                               n00b_result_get_err(hdr_r));
    }

    // 2. Parse load commands (dispatches to segment, symbol, etc. parsing).
    parse_load_commands(stream, bin);

    // 3. Auto-demangle symbol names.
    for (uint32_t i = 0; i < bin->num_symbols; i++) {
        n00b_macho_symbol_t *sym = &bin->symbols[i];
        if (sym->name && sym->name->data && n00b_is_mangled(sym->name->data)) {
            sym->demangled_name = n00b_demangle(sym->name->data);
        }
    }

    return n00b_result_ok(n00b_macho_binary_t *, bin);
}

// ============================================================================
// n00b_macho_parse — handles fat binaries
// ============================================================================

/// Swap a uint32_t from big-endian to host.
static uint32_t
be32_to_host(uint32_t v)
{
    union { uint16_t u; uint8_t b[2]; } probe = {.u = 1};

    if (probe.b[0] == 1) {
        // Little-endian host: swap.
        return ((v >> 24) & 0xFF)
             | ((v >>  8) & 0xFF00)
             | ((v <<  8) & 0xFF0000)
             | ((v << 24) & 0xFF000000);
    }

    return v;
}

n00b_result_t(n00b_macho_fat_t *)
n00b_macho_parse(n00b_bstream_t *stream)
{
    if (!stream) {
        return n00b_result_err(n00b_macho_fat_t *, N00B_ERR_READ);
    }

    // Peek at magic to determine if it's a fat binary.
    n00b_bstream_setpos(stream, 0);

    auto magic_r = n00b_bstream_peek_u32(stream, 0);

    if (n00b_result_is_err(magic_r)) {
        return n00b_result_err(n00b_macho_fat_t *, N00B_ERR_CORRUPTED);
    }

    uint32_t magic = n00b_result_get(magic_r);

    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        // Fat binary — read header (always big-endian).
        n00b_bstream_setpos(stream, 0);
        n00b_bstream_read_u32(stream); // skip magic

        auto nfat_r = n00b_bstream_read_u32(stream);

        if (n00b_result_is_err(nfat_r)) {
            return n00b_result_err(n00b_macho_fat_t *, N00B_ERR_CORRUPTED);
        }

        uint32_t raw_nfat = n00b_result_get(nfat_r);

        // Fat headers are always big-endian.
        uint32_t nfat_arch = be32_to_host(raw_nfat);

        // Sanity check.
        if (nfat_arch > 256) {
            return n00b_result_err(n00b_macho_fat_t *, N00B_ERR_CORRUPTED);
        }

        n00b_macho_fat_t *fat = n00b_alloc(n00b_macho_fat_t);

        fat->binaries = n00b_alloc_array(n00b_macho_binary_t *, nfat_arch);
        fat->count    = 0;
        // Per-slice descriptors, parallel to `binaries` (D-020). Built up
        // alongside the successfully-parsed slices so the indices align.
        fat->slices = n00b_alloc_array(n00b_macho_fat_slice_t, nfat_arch);

        // Read all fat_arch entries first, then parse slices.
        // This avoids stream position issues from parse_single.
        // Fat arch fields are big-endian on disk; convert to host.
        uint32_t *slice_offsets = n00b_alloc_array(uint32_t, nfat_arch);
        uint32_t *slice_cputype = n00b_alloc_array(uint32_t, nfat_arch);
        uint32_t *slice_size    = n00b_alloc_array(uint32_t, nfat_arch);
        uint32_t *slice_align   = n00b_alloc_array(uint32_t, nfat_arch);

        for (uint32_t i = 0; i < nfat_arch; i++) {
            auto cpu_r  = n00b_bstream_read_u32(stream);
            auto sub_r  = n00b_bstream_read_u32(stream);
            auto off_r  = n00b_bstream_read_u32(stream);
            auto sz_r   = n00b_bstream_read_u32(stream);
            auto aln_r  = n00b_bstream_read_u32(stream);

            if (n00b_result_is_err(off_r)) {
                slice_offsets[i] = UINT32_MAX;
            }
            else {
                slice_offsets[i] = be32_to_host(n00b_result_get(off_r));
            }

            slice_cputype[i] = n00b_result_is_ok(cpu_r)
                ? be32_to_host(n00b_result_get(cpu_r)) : 0;
            slice_size[i] = n00b_result_is_ok(sz_r)
                ? be32_to_host(n00b_result_get(sz_r)) : 0;
            slice_align[i] = n00b_result_is_ok(aln_r)
                ? be32_to_host(n00b_result_get(aln_r)) : 0;

            (void)sub_r;
        }

        for (uint32_t i = 0; i < nfat_arch; i++) {
            if (slice_offsets[i] == UINT32_MAX) {
                continue;
            }

            n00b_bstream_setpos(stream, slice_offsets[i]);

            auto bin_r = n00b_macho_parse_single(stream);

            if (n00b_result_is_ok(bin_r)) {
                n00b_macho_binary_t *bin = n00b_result_get(bin_r);

                bin->is_fat     = true;
                bin->fat_offset = slice_offsets[i];

                fat->binaries[fat->count] = bin;
                // Retain this slice's placement/identity (D-020), aligned
                // to the parsed-binary index.
                fat->slices[fat->count].cputype = slice_cputype[i];
                fat->slices[fat->count].offset  = slice_offsets[i];
                fat->slices[fat->count].size    = slice_size[i];
                fat->slices[fat->count].align   = slice_align[i];
                fat->count++;
            }
        }

        if (fat->count == 0) {
            return n00b_result_err(n00b_macho_fat_t *, N00B_ERR_PARSE);
        }

        return n00b_result_ok(n00b_macho_fat_t *, fat);
    }
    else {
        // Single binary — wrap in fat container.
        n00b_bstream_setpos(stream, 0);

        auto bin_r = n00b_macho_parse_single(stream);

        if (n00b_result_is_err(bin_r)) {
            return n00b_result_err(n00b_macho_fat_t *,
                                   n00b_result_get_err(bin_r));
        }

        n00b_macho_fat_t *fat = n00b_alloc(n00b_macho_fat_t);

        fat->binaries    = n00b_alloc_array(n00b_macho_binary_t *, 1);
        fat->binaries[0] = n00b_result_get(bin_r);
        fat->count       = 1;

        return n00b_result_ok(n00b_macho_fat_t *, fat);
    }
}

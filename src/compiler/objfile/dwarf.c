/**
 * @file n00b_dwarf.c
 * @brief DWARF debug information core reader.
 *
 * Parses .debug_abbrev, .debug_info (CU headers + DIEs), .debug_str,
 * and .debug_line sections.  Supports DWARF versions 2-5 in both
 * 32-bit and 64-bit DWARF format.
 *
 * Ported from slop/src/demangle/dwarf/dwarf_reader.c and adapted
 * to lief conventions (n00b allocator, n00b_bstream_t not needed since
 * DWARF sections are already in-memory byte arrays).
 */

#include <string.h>
#include <stdio.h>
#include "compiler/objfile/dwarf.h"
#include "compiler/objfile/elf.h"
#include "compiler/objfile/macho.h"

// ============================================================================
// LEB128 inline decoders
// ============================================================================

static inline uint64_t
dwarf_decode_uleb128(const uint8_t *p, size_t *bytes_read)
{
    uint64_t result = 0;
    unsigned shift  = 0;
    size_t   i      = 0;

    for (;;) {
        uint8_t byte = p[i];
        result |= (uint64_t)(byte & 0x7f) << shift;
        i++;
        if (!(byte & 0x80)) {
            break;
        }
        shift += 7;
    }
    *bytes_read = i;
    return result;
}

static inline int64_t
dwarf_decode_sleb128(const uint8_t *p, size_t *bytes_read)
{
    int64_t  result = 0;
    unsigned shift  = 0;
    size_t   i      = 0;
    uint8_t  byte;

    for (;;) {
        byte = p[i];
        result |= (int64_t)(byte & 0x7f) << shift;
        shift += 7;
        i++;
        if (!(byte & 0x80)) {
            break;
        }
    }
    // Sign extend if the high bit of the last byte was set.
    if (shift < 64 && (byte & 0x40)) {
        result |= -(1LL << shift);
    }
    *bytes_read = i;
    return result;
}

// ============================================================================
// Abbreviation table parser
// ============================================================================

n00b_dwarf_abbrev_table_t *
n00b_dwarf_parse_abbrev_table(const uint8_t *abbrev_data,
                              size_t         abbrev_size,
                              uint64_t       offset)
{
    if (!abbrev_data || offset >= abbrev_size) {
        return nullptr;
    }

    n00b_dwarf_abbrev_table_t *table = n00b_alloc(n00b_dwarf_abbrev_table_t);
    table->count    = 0;
    table->capacity = 16;
    table->entries  = n00b_alloc_array(n00b_dwarf_abbrev_t, table->capacity);

    const uint8_t *p   = abbrev_data + offset;
    const uint8_t *end = abbrev_data + abbrev_size;

    while (p < end) {
        size_t   br;
        uint64_t code = dwarf_decode_uleb128(p, &br);
        p += br;
        if (code == 0) {
            break;  // End of table.
        }

        if (p >= end) {
            break;
        }

        uint64_t tag = dwarf_decode_uleb128(p, &br);
        p += br;
        if (p >= end) {
            break;
        }

        bool has_children = (*p++ == N00B_DW_CHILDREN_yes);

        // Parse attribute specifications.
        size_t                    attr_cap   = 8;
        size_t                    attr_count = 0;
        n00b_dwarf_abbrev_attr_t *attrs =
            n00b_alloc_array(n00b_dwarf_abbrev_attr_t, attr_cap);

        while (p < end) {
            uint64_t aname = dwarf_decode_uleb128(p, &br);
            p += br;
            if (p >= end) {
                break;
            }
            uint64_t aform = dwarf_decode_uleb128(p, &br);
            p += br;

            if (aname == 0 && aform == 0) {
                break;  // End of attr specs.
            }

            if (attr_count >= attr_cap) {
                attr_cap *= 2;
                n00b_dwarf_abbrev_attr_t *new_attrs =
                    n00b_alloc_array(n00b_dwarf_abbrev_attr_t, attr_cap);
                memcpy(new_attrs, attrs,
                       attr_count * sizeof(n00b_dwarf_abbrev_attr_t));
                attrs = new_attrs;
            }

            attrs[attr_count].name = aname;
            attrs[attr_count].form = aform;
            attrs[attr_count].implicit_const = 0;

            // N00B_DW_FORM_implicit_const has an extra SLEB128 value.
            if (aform == N00B_DW_FORM_implicit_const && p < end) {
                attrs[attr_count].implicit_const =
                    dwarf_decode_sleb128(p, &br);
                p += br;
            }

            attr_count++;
        }

        // Add entry to table.
        if (table->count >= table->capacity) {
            table->capacity *= 2;
            n00b_dwarf_abbrev_t *new_entries =
                n00b_alloc_array(n00b_dwarf_abbrev_t, table->capacity);
            memcpy(new_entries, table->entries,
                   table->count * sizeof(n00b_dwarf_abbrev_t));
            table->entries = new_entries;
        }

        n00b_dwarf_abbrev_t *entry = &table->entries[table->count++];
        entry->code         = code;
        entry->tag          = tag;
        entry->has_children = has_children;
        entry->attrs        = attrs;
        entry->attr_count   = attr_count;
    }

    return table;
}

const n00b_dwarf_abbrev_t *
n00b_dwarf_abbrev_find(const n00b_dwarf_abbrev_table_t *table, uint64_t code)
{
    if (!table) {
        return nullptr;
    }
    for (size_t i = 0; i < table->count; i++) {
        if (table->entries[i].code == code) {
            return &table->entries[i];
        }
    }
    return nullptr;
}

// ============================================================================
// CU header parser
// ============================================================================

bool
n00b_dwarf_parse_cu_header(const uint8_t   *info_data,
                           size_t           info_size,
                           size_t           offset,
                           n00b_dwarf_cu_t *out)
{
    if (!info_data || !out) {
        return false;
    }

    memset(out, 0, sizeof(*out));
    out->cu_offset = offset;

    const uint8_t *p   = info_data + offset;
    const uint8_t *end = info_data + info_size;

    if (p + 4 > end) {
        return false;
    }

    // Read unit_length — detect 32-bit vs 64-bit DWARF format.
    uint32_t initial_length;
    memcpy(&initial_length, p, 4);
    p += 4;

    if (initial_length == 0xFFFFFFFF) {
        // 64-bit DWARF format.
        if (p + 8 > end) {
            return false;
        }
        memcpy(&out->unit_length, p, 8);
        p += 8;
        out->is_64bit = true;
    } else {
        out->unit_length = initial_length;
        out->is_64bit    = false;
    }

    // Version.
    if (p + 2 > end) {
        return false;
    }
    memcpy(&out->version, p, 2);
    p += 2;

    if (out->version >= 5) {
        // DWARF 5: unit_type, address_size, then abbrev_offset.
        if (p + 2 > end) {
            return false;
        }
        out->unit_type   = *p++;
        out->address_size = *p++;

        if (out->is_64bit) {
            if (p + 8 > end) {
                return false;
            }
            memcpy(&out->abbrev_offset, p, 8);
            p += 8;
        } else {
            if (p + 4 > end) {
                return false;
            }
            uint32_t off32;
            memcpy(&off32, p, 4);
            out->abbrev_offset = off32;
            p += 4;
        }
    } else {
        // DWARF 2-4: abbrev_offset, then address_size.
        if (out->is_64bit) {
            if (p + 8 > end) {
                return false;
            }
            memcpy(&out->abbrev_offset, p, 8);
            p += 8;
        } else {
            if (p + 4 > end) {
                return false;
            }
            uint32_t off32;
            memcpy(&off32, p, 4);
            out->abbrev_offset = off32;
            p += 4;
        }

        if (p + 1 > end) {
            return false;
        }
        out->address_size = *p++;
        out->unit_type    = 0;
    }

    out->header_size = (size_t)(p - (info_data + offset));
    out->die_offset  = offset + out->header_size;

    return true;
}

// ============================================================================
// Attribute value parser
// ============================================================================

/// Read a single attribute value from `p` according to `form`.
/// Returns the number of bytes consumed, or 0 on error.
static size_t
read_attr_value(n00b_dwarf_info_t    *info,
                const n00b_dwarf_cu_t *cu,
                const uint8_t         *p,
                const uint8_t         *end,
                uint64_t               form,
                int64_t                implicit_const,
                n00b_dwarf_attr_t     *out)
{
    const uint8_t *start = p;
    size_t         br;

    out->form = form;

    switch (form) {
    case N00B_DW_FORM_addr:
        if (p + cu->address_size > end) {
            return SIZE_MAX;
        }
        if (cu->address_size == 8) {
            memcpy(&out->u64, p, 8);
        } else if (cu->address_size == 4) {
            uint32_t v;
            memcpy(&v, p, 4);
            out->u64 = v;
        } else {
            out->u64 = 0;
        }
        p += cu->address_size;
        break;

    case N00B_DW_FORM_data1:
        if (p + 1 > end) {
            return SIZE_MAX;
        }
        out->u64 = *p++;
        break;

    case N00B_DW_FORM_data2:
        if (p + 2 > end) {
            return SIZE_MAX;
        }
        {
            uint16_t v;
            memcpy(&v, p, 2);
            out->u64 = v;
        }
        p += 2;
        break;

    case N00B_DW_FORM_data4:
        if (p + 4 > end) {
            return SIZE_MAX;
        }
        {
            uint32_t v;
            memcpy(&v, p, 4);
            out->u64 = v;
        }
        p += 4;
        break;

    case N00B_DW_FORM_data8:
        if (p + 8 > end) {
            return SIZE_MAX;
        }
        memcpy(&out->u64, p, 8);
        p += 8;
        break;

    case N00B_DW_FORM_data16:
        // 16-byte data — store as block.
        if (p + 16 > end) {
            return SIZE_MAX;
        }
        out->block.data = p;
        out->block.size = 16;
        p += 16;
        break;

    case N00B_DW_FORM_udata:
        out->u64 = dwarf_decode_uleb128(p, &br);
        p += br;
        break;

    case N00B_DW_FORM_sdata:
        out->s64 = dwarf_decode_sleb128(p, &br);
        p += br;
        break;

    case N00B_DW_FORM_string:
        // Inline NUL-terminated string.
        out->str = (const char *)p;
        while (p < end && *p != 0) {
            p++;
        }
        if (p < end) {
            p++;  // Skip NUL.
        }
        break;

    case N00B_DW_FORM_strp:
        // Offset into .debug_str.
        {
            uint64_t str_off;
            if (cu->is_64bit) {
                if (p + 8 > end) {
                    return SIZE_MAX;
                }
                memcpy(&str_off, p, 8);
                p += 8;
            } else {
                if (p + 4 > end) {
                    return SIZE_MAX;
                }
                uint32_t off32;
                memcpy(&off32, p, 4);
                str_off = off32;
                p += 4;
            }
            if (info->debug_str && str_off < info->debug_str_size) {
                out->str = (const char *)(info->debug_str + str_off);
            } else {
                out->str = "";
            }
        }
        break;

    case N00B_DW_FORM_line_strp:
        // Offset into .debug_line_str.
        {
            uint64_t str_off;
            if (cu->is_64bit) {
                if (p + 8 > end) {
                    return SIZE_MAX;
                }
                memcpy(&str_off, p, 8);
                p += 8;
            } else {
                if (p + 4 > end) {
                    return SIZE_MAX;
                }
                uint32_t off32;
                memcpy(&off32, p, 4);
                str_off = off32;
                p += 4;
            }
            if (info->debug_line_str && str_off < info->debug_line_str_size) {
                out->str = (const char *)(info->debug_line_str + str_off);
            } else {
                out->str = "";
            }
        }
        break;

    case N00B_DW_FORM_strx:
    case N00B_DW_FORM_strx1:
    case N00B_DW_FORM_strx2:
    case N00B_DW_FORM_strx3:
    case N00B_DW_FORM_strx4:
        // DWARF 5 string index into .debug_str_offsets → .debug_str.
        {
            uint64_t index;
            if (form == N00B_DW_FORM_strx) {
                index = dwarf_decode_uleb128(p, &br);
                p += br;
            } else if (form == N00B_DW_FORM_strx1) {
                if (p + 1 > end) {
                    return SIZE_MAX;
                }
                index = *p++;
            } else if (form == N00B_DW_FORM_strx2) {
                if (p + 2 > end) {
                    return SIZE_MAX;
                }
                uint16_t v;
                memcpy(&v, p, 2);
                index = v;
                p += 2;
            } else if (form == N00B_DW_FORM_strx3) {
                if (p + 3 > end) {
                    return SIZE_MAX;
                }
                index = p[0] | ((uint64_t)p[1] << 8)
                      | ((uint64_t)p[2] << 16);
                p += 3;
            } else {
                // strx4
                if (p + 4 > end) {
                    return SIZE_MAX;
                }
                uint32_t v;
                memcpy(&v, p, 4);
                index = v;
                p += 4;
            }

            // Resolve: str_offsets_base + index * offset_size → offset in .debug_str
            out->str = "";
            if (info->debug_str_offsets && info->debug_str) {
                size_t offset_size = cu->is_64bit ? 8 : 4;
                size_t table_off   = cu->str_offsets_base
                                   + index * offset_size;
                if (table_off + offset_size
                    <= info->debug_str_offsets_size) {
                    uint64_t str_off;
                    if (cu->is_64bit) {
                        memcpy(&str_off,
                               info->debug_str_offsets + table_off, 8);
                    } else {
                        uint32_t off32;
                        memcpy(&off32,
                               info->debug_str_offsets + table_off, 4);
                        str_off = off32;
                    }
                    if (str_off < info->debug_str_size) {
                        out->str =
                            (const char *)(info->debug_str + str_off);
                    }
                }
            }
        }
        break;

    case N00B_DW_FORM_addrx:
    case N00B_DW_FORM_addrx1:
    case N00B_DW_FORM_addrx2:
    case N00B_DW_FORM_addrx3:
    case N00B_DW_FORM_addrx4:
        // DWARF 5 address index.
        {
            uint64_t index;
            if (form == N00B_DW_FORM_addrx) {
                index = dwarf_decode_uleb128(p, &br);
                p += br;
            } else if (form == N00B_DW_FORM_addrx1) {
                if (p + 1 > end) {
                    return SIZE_MAX;
                }
                index = *p++;
            } else if (form == N00B_DW_FORM_addrx2) {
                if (p + 2 > end) {
                    return SIZE_MAX;
                }
                uint16_t v;
                memcpy(&v, p, 2);
                index = v;
                p += 2;
            } else if (form == N00B_DW_FORM_addrx3) {
                if (p + 3 > end) {
                    return SIZE_MAX;
                }
                index = p[0] | ((uint64_t)p[1] << 8)
                      | ((uint64_t)p[2] << 16);
                p += 3;
            } else {
                if (p + 4 > end) {
                    return SIZE_MAX;
                }
                uint32_t v;
                memcpy(&v, p, 4);
                index = v;
                p += 4;
            }

            out->u64 = 0;
            if (info->debug_addr) {
                size_t entry_off = cu->addr_base
                                 + index * cu->address_size;
                if (entry_off + cu->address_size
                    <= info->debug_addr_size) {
                    if (cu->address_size == 8) {
                        memcpy(&out->u64,
                               info->debug_addr + entry_off, 8);
                    } else if (cu->address_size == 4) {
                        uint32_t v;
                        memcpy(&v,
                               info->debug_addr + entry_off, 4);
                        out->u64 = v;
                    }
                }
            }
        }
        break;

    case N00B_DW_FORM_ref1:
        if (p + 1 > end) {
            return SIZE_MAX;
        }
        out->u64 = cu->cu_offset + *p++;
        break;

    case N00B_DW_FORM_ref2:
        if (p + 2 > end) {
            return SIZE_MAX;
        }
        {
            uint16_t v;
            memcpy(&v, p, 2);
            out->u64 = cu->cu_offset + v;
        }
        p += 2;
        break;

    case N00B_DW_FORM_ref4:
        if (p + 4 > end) {
            return SIZE_MAX;
        }
        {
            uint32_t v;
            memcpy(&v, p, 4);
            out->u64 = cu->cu_offset + v;
        }
        p += 4;
        break;

    case N00B_DW_FORM_ref8:
        if (p + 8 > end) {
            return SIZE_MAX;
        }
        {
            uint64_t v;
            memcpy(&v, p, 8);
            out->u64 = cu->cu_offset + v;
        }
        p += 8;
        break;

    case N00B_DW_FORM_ref_udata:
        {
            uint64_t v = dwarf_decode_uleb128(p, &br);
            out->u64 = cu->cu_offset + v;
            p += br;
        }
        break;

    case N00B_DW_FORM_ref_addr:
        // Absolute reference (section-relative).
        if (cu->version >= 3) {
            // DWARF 3+: same size as sec_offset.
            if (cu->is_64bit) {
                if (p + 8 > end) {
                    return SIZE_MAX;
                }
                memcpy(&out->u64, p, 8);
                p += 8;
            } else {
                if (p + 4 > end) {
                    return SIZE_MAX;
                }
                uint32_t v;
                memcpy(&v, p, 4);
                out->u64 = v;
                p += 4;
            }
        } else {
            // DWARF 2: address-sized.
            if (p + cu->address_size > end) {
                return SIZE_MAX;
            }
            if (cu->address_size == 8) {
                memcpy(&out->u64, p, 8);
            } else {
                uint32_t v;
                memcpy(&v, p, 4);
                out->u64 = v;
            }
            p += cu->address_size;
        }
        break;

    case N00B_DW_FORM_ref_sig8:
        if (p + 8 > end) {
            return SIZE_MAX;
        }
        memcpy(&out->u64, p, 8);
        p += 8;
        break;

    case N00B_DW_FORM_sec_offset:
        if (cu->is_64bit) {
            if (p + 8 > end) {
                return SIZE_MAX;
            }
            memcpy(&out->u64, p, 8);
            p += 8;
        } else {
            if (p + 4 > end) {
                return SIZE_MAX;
            }
            uint32_t v;
            memcpy(&v, p, 4);
            out->u64 = v;
            p += 4;
        }
        break;

    case N00B_DW_FORM_exprloc:
        {
            uint64_t len = dwarf_decode_uleb128(p, &br);
            p += br;
            if (p + len > end) {
                return SIZE_MAX;
            }
            out->block.data = p;
            out->block.size = len;
            p += len;
        }
        break;

    case N00B_DW_FORM_block1:
        if (p + 1 > end) {
            return SIZE_MAX;
        }
        {
            uint8_t len = *p++;
            if (p + len > end) {
                return SIZE_MAX;
            }
            out->block.data = p;
            out->block.size = len;
            p += len;
        }
        break;

    case N00B_DW_FORM_block2:
        if (p + 2 > end) {
            return SIZE_MAX;
        }
        {
            uint16_t len;
            memcpy(&len, p, 2);
            p += 2;
            if (p + len > end) {
                return SIZE_MAX;
            }
            out->block.data = p;
            out->block.size = len;
            p += len;
        }
        break;

    case N00B_DW_FORM_block4:
        if (p + 4 > end) {
            return SIZE_MAX;
        }
        {
            uint32_t len;
            memcpy(&len, p, 4);
            p += 4;
            if (p + len > end) {
                return SIZE_MAX;
            }
            out->block.data = p;
            out->block.size = len;
            p += len;
        }
        break;

    case N00B_DW_FORM_block:
        {
            uint64_t len = dwarf_decode_uleb128(p, &br);
            p += br;
            if (p + len > end) {
                return SIZE_MAX;
            }
            out->block.data = p;
            out->block.size = len;
            p += len;
        }
        break;

    case N00B_DW_FORM_flag:
        if (p + 1 > end) {
            return SIZE_MAX;
        }
        out->u64 = *p++;
        break;

    case N00B_DW_FORM_flag_present:
        // No data in stream — value is implicitly 1.
        out->u64 = 1;
        break;

    case N00B_DW_FORM_implicit_const:
        out->s64 = implicit_const;
        break;

    case N00B_DW_FORM_loclistx:
    case N00B_DW_FORM_rnglistx:
        out->u64 = dwarf_decode_uleb128(p, &br);
        p += br;
        break;

    case N00B_DW_FORM_ref_sup4:
        if (p + 4 > end) {
            return SIZE_MAX;
        }
        {
            uint32_t v;
            memcpy(&v, p, 4);
            out->u64 = v;
        }
        p += 4;
        break;

    case N00B_DW_FORM_ref_sup8:
        if (p + 8 > end) {
            return SIZE_MAX;
        }
        memcpy(&out->u64, p, 8);
        p += 8;
        break;

    case N00B_DW_FORM_strp_sup:
        if (cu->is_64bit) {
            if (p + 8 > end) {
                return SIZE_MAX;
            }
            memcpy(&out->u64, p, 8);
            p += 8;
        } else {
            if (p + 4 > end) {
                return SIZE_MAX;
            }
            uint32_t v;
            memcpy(&v, p, 4);
            out->u64 = v;
            p += 4;
        }
        out->str = "";  // Supplementary string — not resolved here.
        break;

    case N00B_DW_FORM_indirect:
        // Read actual form, then recurse.
        {
            uint64_t real_form = dwarf_decode_uleb128(p, &br);
            p += br;
            size_t consumed = read_attr_value(info, cu, p, end,
                                              real_form, 0, out);
            if (consumed == SIZE_MAX) {
                return SIZE_MAX;
            }
            p += consumed;
            out->form = real_form;
        }
        break;

    default:
        // Unknown form — cannot continue.
        return SIZE_MAX;
    }

    return (size_t)(p - start);
}

// ============================================================================
// DIE parser
// ============================================================================

bool
n00b_dwarf_parse_die(n00b_dwarf_info_t         *info,
                     n00b_dwarf_abbrev_table_t *abbrev_table,
                     const n00b_dwarf_cu_t     *cu,
                     size_t                     offset,
                     n00b_dwarf_die_t          *out)
{
    if (!info || !abbrev_table || !cu || !out) {
        return false;
    }

    const uint8_t *data = info->debug_info;
    const uint8_t *end  = data + info->debug_info_size;

    if (offset >= info->debug_info_size) {
        return false;
    }

    memset(out, 0, sizeof(*out));
    out->offset = offset;

    const uint8_t *p  = data + offset;
    size_t         br;
    uint64_t       abbrev_code = dwarf_decode_uleb128(p, &br);
    p += br;

    if (abbrev_code == 0) {
        // Null DIE (end of sibling chain).
        out->tag         = 0;
        out->next_offset = (size_t)(p - data);
        return true;
    }

    const n00b_dwarf_abbrev_t *abbrev =
        n00b_dwarf_abbrev_find(abbrev_table, abbrev_code);
    if (!abbrev) {
        return false;
    }

    out->tag          = abbrev->tag;
    out->has_children = abbrev->has_children;
    out->attr_count   = abbrev->attr_count;

    if (abbrev->attr_count > 0) {
        out->attrs = n00b_alloc_array(n00b_dwarf_attr_t, abbrev->attr_count);

        for (size_t i = 0; i < abbrev->attr_count; i++) {
            out->attrs[i].name = abbrev->attrs[i].name;
            size_t consumed = read_attr_value(
                info, cu, p, end,
                abbrev->attrs[i].form,
                abbrev->attrs[i].implicit_const,
                &out->attrs[i]);
            if (consumed == SIZE_MAX) {
                return false;
            }
            p += consumed;
        }
    }

    out->next_offset = (size_t)(p - data);
    return true;
}

const n00b_dwarf_attr_t *
n00b_dwarf_die_get_attr(const n00b_dwarf_die_t *die, uint64_t name)
{
    if (!die || !die->attrs) {
        return nullptr;
    }
    for (size_t i = 0; i < die->attr_count; i++) {
        if (die->attrs[i].name == name) {
            return &die->attrs[i];
        }
    }
    return nullptr;
}

// ============================================================================
// DIE skipper (skip without full parse)
// ============================================================================

/// Skip past all attribute values for an abbreviation entry.
static size_t
skip_attr_values(n00b_dwarf_info_t         *info,
                 const n00b_dwarf_cu_t     *cu,
                 const n00b_dwarf_abbrev_t *abbrev,
                 const uint8_t             *p,
                 const uint8_t             *end)
{
    const uint8_t *start = p;

    for (size_t i = 0; i < abbrev->attr_count; i++) {
        n00b_dwarf_attr_t dummy = {0};
        size_t consumed = read_attr_value(
            info, cu, p, end,
            abbrev->attrs[i].form,
            abbrev->attrs[i].implicit_const,
            &dummy);
        if (consumed == SIZE_MAX) {
            return 0;
        }
        p += consumed;
    }

    return (size_t)(p - start);
}

size_t
n00b_dwarf_skip_die(n00b_dwarf_info_t         *info,
                    n00b_dwarf_abbrev_table_t *abbrev_table,
                    const n00b_dwarf_cu_t     *cu,
                    size_t                     offset)
{
    if (!info || !abbrev_table || !cu) {
        return 0;
    }

    const uint8_t *data = info->debug_info;
    const uint8_t *end  = data + info->debug_info_size;

    if (offset >= info->debug_info_size) {
        return 0;
    }

    const uint8_t *p  = data + offset;
    size_t         br;
    uint64_t       abbrev_code = dwarf_decode_uleb128(p, &br);
    p += br;

    if (abbrev_code == 0) {
        return (size_t)(p - data);
    }

    const n00b_dwarf_abbrev_t *abbrev =
        n00b_dwarf_abbrev_find(abbrev_table, abbrev_code);
    if (!abbrev) {
        return 0;
    }

    size_t consumed = skip_attr_values(info, cu, abbrev, p, end);
    if (consumed == 0 && abbrev->attr_count > 0) {
        return 0;
    }
    p += consumed;

    return (size_t)(p - data);
}

// ============================================================================
// DWARF 5 base attribute extraction
// ============================================================================

/// Parse the root DIE of a CU to extract str_offsets_base and addr_base.
static void
parse_cu_bases(n00b_dwarf_info_t         *info,
               n00b_dwarf_abbrev_table_t *abbrev_table,
               n00b_dwarf_cu_t           *cu)
{
    if (cu->bases_parsed) {
        return;
    }
    cu->bases_parsed = true;

    if (cu->version < 5) {
        return;
    }

    n00b_dwarf_die_t die = {0};
    if (!n00b_dwarf_parse_die(info, abbrev_table, cu, cu->die_offset, &die)) {
        return;
    }

    const n00b_dwarf_attr_t *a;
    a = n00b_dwarf_die_get_attr(&die, N00B_DW_AT_str_offsets_base);
    if (a) {
        cu->str_offsets_base = a->u64;
    }
    a = n00b_dwarf_die_get_attr(&die, N00B_DW_AT_addr_base);
    if (a) {
        cu->addr_base = a->u64;
    }
}

// ============================================================================
// Abbreviation table cache
// ============================================================================

static n00b_dwarf_abbrev_table_t *
get_abbrev_table(n00b_dwarf_info_t *info, uint64_t offset)
{
    // Check cache first.
    for (size_t i = 0; i < info->abbrev_table_count; i++) {
        // Use the first entry's offset to identify tables (since each table
        // starts at a unique offset in .debug_abbrev).  We store the offset
        // in a simple parallel scheme: even indices are offsets, odd are tables.
        // Actually, simpler: just parse and cache sequentially.
    }

    // Parse fresh.
    n00b_dwarf_abbrev_table_t *table =
        n00b_dwarf_parse_abbrev_table(info->debug_abbrev,
                                      info->debug_abbrev_size,
                                      offset);
    if (!table) {
        return nullptr;
    }

    // Add to cache.
    if (info->abbrev_table_count >= info->abbrev_table_cap) {
        size_t new_cap = info->abbrev_table_cap ? info->abbrev_table_cap * 2 : 8;
        n00b_dwarf_abbrev_table_t **new_tables =
            n00b_alloc_array(n00b_dwarf_abbrev_table_t *, new_cap);
        if (info->abbrev_tables) {
            memcpy(new_tables, info->abbrev_tables,
                   info->abbrev_table_count * sizeof(n00b_dwarf_abbrev_table_t *));
        }
        info->abbrev_tables    = new_tables;
        info->abbrev_table_cap = new_cap;
    }
    info->abbrev_tables[info->abbrev_table_count++] = table;

    return table;
}

// ============================================================================
// Top-level section parser
// ============================================================================

n00b_result_t(n00b_dwarf_info_t *)
n00b_dwarf_parse_sections(const uint8_t *debug_info,   size_t info_size,
                          const uint8_t *debug_abbrev, size_t abbrev_size,
                          const uint8_t *debug_str,    size_t str_size,
                          const uint8_t *debug_line,   size_t line_size)
{
    n00b_dwarf_info_t *dw = n00b_alloc(n00b_dwarf_info_t);
    memset(dw, 0, sizeof(*dw));

    dw->debug_info      = debug_info;
    dw->debug_info_size = info_size;
    dw->debug_abbrev      = debug_abbrev;
    dw->debug_abbrev_size = abbrev_size;
    dw->debug_str       = debug_str;
    dw->debug_str_size  = str_size;
    dw->debug_line      = debug_line;
    dw->debug_line_size = line_size;

    if (!debug_info || info_size == 0) {
        return n00b_result_ok(n00b_dwarf_info_t *, dw);
    }

    // Count CUs first.
    size_t cu_count = 0;
    size_t offset   = 0;
    while (offset < info_size) {
        n00b_dwarf_cu_t tmp = {0};
        if (!n00b_dwarf_parse_cu_header(debug_info, info_size, offset, &tmp)) {
            break;
        }
        cu_count++;
        // Advance past CU: initial_length field size + unit_length.
        size_t initial_field_size = tmp.is_64bit ? 12 : 4;
        offset += initial_field_size + tmp.unit_length;
    }

    dw->num_cus = cu_count;
    if (cu_count > 0) {
        dw->cus = n00b_alloc_array(n00b_dwarf_cu_t, cu_count);

        offset = 0;
        for (size_t i = 0; i < cu_count; i++) {
            n00b_dwarf_parse_cu_header(debug_info, info_size, offset,
                                       &dw->cus[i]);
            size_t initial_field_size = dw->cus[i].is_64bit ? 12 : 4;
            offset += initial_field_size + dw->cus[i].unit_length;
        }

        // Parse DWARF 5 base attributes for each CU.
        for (size_t i = 0; i < cu_count; i++) {
            if (dw->cus[i].version >= 5 && debug_abbrev) {
                n00b_dwarf_abbrev_table_t *table =
                    get_abbrev_table(dw, dw->cus[i].abbrev_offset);
                if (table) {
                    parse_cu_bases(dw, table, &dw->cus[i]);
                }
            }
        }
    }

    return n00b_result_ok(n00b_dwarf_info_t *, dw);
}

// ============================================================================
// Section extraction: ELF
// ============================================================================

bool
n00b_dwarf_has_info(n00b_elf_binary_t *bin)
{
    return n00b_option_is_set(n00b_elf_section_by_name(bin, ".debug_info"));
}

/// Helper: get section data pointer and size from an ELF section.
static void
elf_section_data(n00b_elf_binary_t *bin, const char *name,
                 const uint8_t **out_data, size_t *out_size)
{
    *out_data = nullptr;
    *out_size = 0;

    n00b_option_t(n00b_elf_section_t *) sec_opt
        = n00b_elf_section_by_name(bin, name);
    if (!n00b_option_is_set(sec_opt)) {
        return;
    }
    n00b_elf_section_t *sec = n00b_option_get(sec_opt);
    if (sec->content) {
        *out_data = (const uint8_t *)sec->content->data;
        *out_size = n00b_buffer_len(sec->content);
    }
}

n00b_result_t(n00b_dwarf_info_t *)
n00b_dwarf_parse_elf(n00b_elf_binary_t *bin)
{
    if (!bin) {
        return n00b_result_err(n00b_dwarf_info_t *, N00B_ERR_PARSE);
    }

    const uint8_t *info_data, *abbrev_data, *str_data, *line_data;
    size_t         info_size, abbrev_size, str_size, line_size;

    elf_section_data(bin, ".debug_info",   &info_data, &info_size);
    elf_section_data(bin, ".debug_abbrev", &abbrev_data, &abbrev_size);
    elf_section_data(bin, ".debug_str",    &str_data, &str_size);
    elf_section_data(bin, ".debug_line",   &line_data, &line_size);

    n00b_result_t(n00b_dwarf_info_t *) r =
        n00b_dwarf_parse_sections(info_data, info_size,
                                  abbrev_data, abbrev_size,
                                  str_data, str_size,
                                  line_data, line_size);

    if (n00b_result_is_ok(r)) {
        n00b_dwarf_info_t *dw = n00b_result_get(r);

        // Also extract DWARF 5 sections.
        elf_section_data(bin, ".debug_str_offsets",
                         &dw->debug_str_offsets, &dw->debug_str_offsets_size);
        elf_section_data(bin, ".debug_addr",
                         &dw->debug_addr, &dw->debug_addr_size);
        elf_section_data(bin, ".debug_ranges",
                         &dw->debug_ranges, &dw->debug_ranges_size);
        elf_section_data(bin, ".debug_rnglists",
                         &dw->debug_rnglists, &dw->debug_rnglists_size);
        elf_section_data(bin, ".debug_line_str",
                         &dw->debug_line_str, &dw->debug_line_str_size);
        elf_section_data(bin, ".debug_loclists",
                         &dw->debug_loclists, &dw->debug_loclists_size);
    }

    return r;
}

// ============================================================================
// Section extraction: Mach-O
// ============================================================================

bool
n00b_dwarf_has_info_macho(n00b_macho_binary_t *bin)
{
    return n00b_option_is_set(
        n00b_macho_section_by_name(bin, "__DWARF", "__debug_info"));
}

/// Helper: get section data pointer and size from a Mach-O section.
static void
macho_section_data(n00b_macho_binary_t *bin,
                   const char *sectname,
                   const uint8_t **out_data, size_t *out_size)
{
    *out_data = nullptr;
    *out_size = 0;

    n00b_option_t(n00b_macho_section_t *) sec_opt
        = n00b_macho_section_by_name(bin, "__DWARF", sectname);
    if (n00b_option_is_set(sec_opt)) {
        n00b_macho_section_t *sec = n00b_option_get(sec_opt);
        if (sec->content) {
            *out_data = (const uint8_t *)sec->content->data;
            *out_size = n00b_buffer_len(sec->content);
        }
    }
}

n00b_result_t(n00b_dwarf_info_t *)
n00b_dwarf_parse_macho(n00b_macho_binary_t *bin)
{
    if (!bin) {
        return n00b_result_err(n00b_dwarf_info_t *, N00B_ERR_PARSE);
    }

    const uint8_t *info_data, *abbrev_data, *str_data, *line_data;
    size_t         info_size, abbrev_size, str_size, line_size;

    macho_section_data(bin, "__debug_info",   &info_data, &info_size);
    macho_section_data(bin, "__debug_abbrev", &abbrev_data, &abbrev_size);
    macho_section_data(bin, "__debug_str",    &str_data, &str_size);
    macho_section_data(bin, "__debug_line",   &line_data, &line_size);

    n00b_result_t(n00b_dwarf_info_t *) r =
        n00b_dwarf_parse_sections(info_data, info_size,
                                  abbrev_data, abbrev_size,
                                  str_data, str_size,
                                  line_data, line_size);

    if (n00b_result_is_ok(r)) {
        n00b_dwarf_info_t *dw = n00b_result_get(r);
        macho_section_data(bin, "__debug_str_offs",
                           &dw->debug_str_offsets, &dw->debug_str_offsets_size);
        macho_section_data(bin, "__debug_addr",
                           &dw->debug_addr, &dw->debug_addr_size);
        macho_section_data(bin, "__debug_ranges",
                           &dw->debug_ranges, &dw->debug_ranges_size);
        macho_section_data(bin, "__debug_rnglists",
                           &dw->debug_rnglists, &dw->debug_rnglists_size);
        macho_section_data(bin, "__debug_line_str",
                           &dw->debug_line_str, &dw->debug_line_str_size);
        macho_section_data(bin, "__debug_loclists",
                           &dw->debug_loclists, &dw->debug_loclists_size);
    }

    return r;
}

// ============================================================================
// Line number table reader (Phase 10e)
// ============================================================================

/// Parse a DWARF 4 file entry from a line program header.
static size_t
parse_line_file_entry_v4(const uint8_t *p, const uint8_t *end,
                         const char **out_name, uint64_t *out_dir_index)
{
    const uint8_t *start = p;

    // Name (null-terminated string).
    *out_name = (const char *)p;
    while (p < end && *p != 0) {
        p++;
    }
    if (p >= end) {
        return 0;
    }
    p++;  // skip NUL

    size_t br;
    *out_dir_index = dwarf_decode_uleb128(p, &br);
    p += br;
    // Skip timestamp.
    dwarf_decode_uleb128(p, &br);
    p += br;
    // Skip file size.
    dwarf_decode_uleb128(p, &br);
    p += br;

    return (size_t)(p - start);
}

n00b_result_t(bool)
n00b_dwarf_parse_line_table(n00b_dwarf_info_t *info)
{
    if (!info) {
        return n00b_result_err(bool, N00B_ERR_PARSE);
    }
    if (info->lines_parsed) {
        return n00b_result_ok(bool, true);
    }
    info->lines_parsed = true;

    if (!info->debug_line || info->debug_line_size == 0) {
        return n00b_result_ok(bool, true);
    }

    // Temporary dynamic array for collected line entries.
    size_t                   entry_cap   = 256;
    size_t                   entry_count = 0;
    n00b_dwarf_line_entry_t *entries =
        n00b_alloc_array(n00b_dwarf_line_entry_t, entry_cap);

    const uint8_t *base = info->debug_line;
    const uint8_t *end  = base + info->debug_line_size;
    size_t         off  = 0;

    while (off < info->debug_line_size) {
        const uint8_t *p = base + off;

        // --- Line program header ---
        if (p + 4 > end) {
            break;
        }
        uint32_t initial_length;
        memcpy(&initial_length, p, 4);
        p += 4;

        bool     is_64bit    = false;
        uint64_t unit_length = initial_length;

        if (initial_length == 0xFFFFFFFF) {
            if (p + 8 > end) {
                break;
            }
            memcpy(&unit_length, p, 8);
            p += 8;
            is_64bit = true;
        }

        const uint8_t *unit_end = p + unit_length;
        if (unit_end > end) {
            break;
        }

        // Advance off past this entire unit for next iteration.
        off = (size_t)(unit_end - base);

        if (p + 2 > unit_end) {
            continue;
        }
        uint16_t version;
        memcpy(&version, p, 2);
        p += 2;

        // DWARF 5: address_size and segment_selector_size before header_length.
        uint8_t address_size      = 8;  // default
        if (version >= 5) {
            if (p + 2 > unit_end) {
                continue;
            }
            address_size = *p++;
            p++;  // segment_selector_size (skip)
        }

        // header_length
        uint64_t header_length;
        if (is_64bit) {
            if (p + 8 > unit_end) {
                continue;
            }
            memcpy(&header_length, p, 8);
            p += 8;
        } else {
            if (p + 4 > unit_end) {
                continue;
            }
            uint32_t hl32;
            memcpy(&hl32, p, 4);
            header_length = hl32;
            p += 4;
        }
        const uint8_t *header_end = p + header_length;
        if (header_end > unit_end) {
            continue;
        }

        if (p + 4 > header_end) {
            continue;
        }
        uint8_t min_insn_length = *p++;
        uint8_t max_ops_per_insn = 1;
        if (version >= 4) {
            max_ops_per_insn = *p++;
        }
        (void)max_ops_per_insn;  // Used in VLIW; ignored for now.
        bool    default_is_stmt = (*p++ != 0);
        int8_t  line_base       = (int8_t)*p++;

        if (p + 2 > header_end) {
            continue;
        }
        uint8_t line_range  = *p++;
        uint8_t opcode_base = *p++;

        // Standard opcode lengths.
        if (p + (opcode_base - 1) > header_end) {
            continue;
        }
        p += (opcode_base - 1);  // skip standard_opcode_lengths

        // Directories and files.
        size_t       dir_cap   = 16;
        size_t       dir_count = 0;
        const char **dirs      = n00b_alloc_array(const char *, dir_cap);

        size_t       file_cap   = 16;
        size_t       file_count = 0;
        const char **files      = n00b_alloc_array(const char *, file_cap);
        // File index 0 is "no file" in DWARF 4.
        files[file_count++] = "";

        if (version < 5) {
            // DWARF 2-4: null-terminated directory list.
            while (p < header_end && *p != 0) {
                if (dir_count >= dir_cap) {
                    dir_cap *= 2;
                    const char **nd = n00b_alloc_array(const char *, dir_cap);
                    memcpy(nd, dirs, dir_count * sizeof(const char *));
                    dirs = nd;
                }
                dirs[dir_count++] = (const char *)p;
                while (p < header_end && *p != 0) {
                    p++;
                }
                p++;  // skip NUL
            }
            if (p < header_end) {
                p++;  // skip final NUL
            }

            // File list.
            while (p < header_end && *p != 0) {
                const char *fname;
                uint64_t    dindex;
                size_t      consumed =
                    parse_line_file_entry_v4(p, header_end, &fname, &dindex);
                if (consumed == 0) {
                    break;
                }
                p += consumed;

                if (file_count >= file_cap) {
                    file_cap *= 2;
                    const char **nf =
                        n00b_alloc_array(const char *, file_cap);
                    memcpy(nf, files, file_count * sizeof(const char *));
                    files = nf;
                }
                files[file_count++] = fname;
            }
            if (p < header_end) {
                p++;  // skip final NUL
            }
        } else {
            // DWARF 5: format descriptors.
            // Directory entries.
            if (p + 1 > header_end) {
                goto skip_program;
            }
            uint8_t dir_entry_format_count = *p++;
            // Skip format pairs for directories.
            size_t br;
            for (uint8_t i = 0; i < dir_entry_format_count; i++) {
                dwarf_decode_uleb128(p, &br); p += br; // content type
                dwarf_decode_uleb128(p, &br); p += br; // form
            }
            uint64_t dir_entries = dwarf_decode_uleb128(p, &br);
            p += br;

            for (uint64_t i = 0; i < dir_entries; i++) {
                // For simplicity, assume first format is N00B_DW_LNCT_path with
                // N00B_DW_FORM_string or N00B_DW_FORM_line_strp.
                // This is a simplification — real code would decode per format.
                if (dir_count >= dir_cap) {
                    dir_cap *= 2;
                    const char **nd = n00b_alloc_array(const char *, dir_cap);
                    memcpy(nd, dirs, dir_count * sizeof(const char *));
                    dirs = nd;
                }
                // Try to extract inline string.
                if (p < header_end && *p != 0) {
                    dirs[dir_count++] = (const char *)p;
                    while (p < header_end && *p != 0) {
                        p++;
                    }
                    if (p < header_end) {
                        p++;
                    }
                } else {
                    // Could be line_strp or other form — skip 4 bytes.
                    dirs[dir_count++] = "";
                    p += 4;
                }
            }

            // File entries.
            if (p + 1 > header_end) {
                goto skip_program;
            }
            uint8_t file_entry_format_count = *p++;
            for (uint8_t i = 0; i < file_entry_format_count; i++) {
                dwarf_decode_uleb128(p, &br); p += br;
                dwarf_decode_uleb128(p, &br); p += br;
            }
            uint64_t file_entries_count = dwarf_decode_uleb128(p, &br);
            p += br;

            // Reset file list for DWARF 5 (0-indexed).
            file_count = 0;
            for (uint64_t i = 0; i < file_entries_count; i++) {
                if (file_count >= file_cap) {
                    file_cap *= 2;
                    const char **nf =
                        n00b_alloc_array(const char *, file_cap);
                    memcpy(nf, files, file_count * sizeof(const char *));
                    files = nf;
                }
                if (p < header_end && *p != 0) {
                    files[file_count++] = (const char *)p;
                    while (p < header_end && *p != 0) {
                        p++;
                    }
                    if (p < header_end) {
                        p++;
                    }
                } else {
                    files[file_count++] = "";
                    p += 4;
                }
                // Skip directory_index if present.
                if (file_entry_format_count > 1 && p < header_end) {
                    dwarf_decode_uleb128(p, &br);
                    p += br;
                }
                // Skip remaining format entries.
                for (uint8_t j = 2; j < file_entry_format_count; j++) {
                    if (p < header_end) {
                        dwarf_decode_uleb128(p, &br);
                        p += br;
                    }
                }
            }
        }

        // Jump to the start of the line program opcodes.
        p = header_end;

        // --- State machine ---
        uint64_t sm_address       = 0;
        uint32_t sm_file          = 1;
        uint32_t sm_line          = 1;
        uint16_t sm_column        = 0;
        bool     sm_is_stmt       = default_is_stmt;
        bool     sm_end_sequence  = false;
        (void)sm_end_sequence;  // Tracked for spec completeness.

        while (p < unit_end) {
            uint8_t opcode = *p++;

            if (opcode == 0) {
                // Extended opcode.
                if (p >= unit_end) {
                    break;
                }
                size_t   br2;
                uint64_t ext_len = dwarf_decode_uleb128(p, &br2);
                p += br2;
                if (p >= unit_end || ext_len == 0) {
                    break;
                }
                const uint8_t *ext_end = p + ext_len;
                uint8_t ext_opcode = *p++;

                switch (ext_opcode) {
                case N00B_DW_LNE_end_sequence:
                    sm_end_sequence = true;
                    // Emit row.
                    if (entry_count >= entry_cap) {
                        entry_cap *= 2;
                        n00b_dwarf_line_entry_t *ne =
                            n00b_alloc_array(n00b_dwarf_line_entry_t, entry_cap);
                        memcpy(ne, entries, entry_count * sizeof(*ne));
                        entries = ne;
                    }
                    entries[entry_count].address      = sm_address;
                    entries[entry_count].file =
                        (sm_file < file_count) ? files[sm_file] : "";
                    entries[entry_count].line         = sm_line;
                    entries[entry_count].column        = sm_column;
                    entries[entry_count].is_stmt       = sm_is_stmt;
                    entries[entry_count].end_sequence  = true;
                    entry_count++;

                    // Reset state.
                    sm_address      = 0;
                    sm_file         = 1;
                    sm_line         = 1;
                    sm_column       = 0;
                    sm_is_stmt      = default_is_stmt;
                    sm_end_sequence = false;
                    break;

                case N00B_DW_LNE_set_address:
                    if (address_size == 8 && p + 8 <= ext_end) {
                        memcpy(&sm_address, p, 8);
                    } else if (address_size == 4 && p + 4 <= ext_end) {
                        uint32_t a;
                        memcpy(&a, p, 4);
                        sm_address = a;
                    }
                    break;

                case N00B_DW_LNE_set_discriminator:
                    // Read and discard discriminator.
                    break;

                case N00B_DW_LNE_define_file:
                    // Rare; skip.
                    break;

                default:
                    break;
                }
                p = ext_end;
            } else if (opcode < opcode_base) {
                // Standard opcode.
                switch (opcode) {
                case N00B_DW_LNS_copy:
                    if (entry_count >= entry_cap) {
                        entry_cap *= 2;
                        n00b_dwarf_line_entry_t *ne =
                            n00b_alloc_array(n00b_dwarf_line_entry_t, entry_cap);
                        memcpy(ne, entries, entry_count * sizeof(*ne));
                        entries = ne;
                    }
                    entries[entry_count].address     = sm_address;
                    entries[entry_count].file =
                        (sm_file < file_count) ? files[sm_file] : "";
                    entries[entry_count].line        = sm_line;
                    entries[entry_count].column       = sm_column;
                    entries[entry_count].is_stmt      = sm_is_stmt;
                    entries[entry_count].end_sequence = false;
                    entry_count++;
                    break;

                case N00B_DW_LNS_advance_pc: {
                    size_t   br3;
                    uint64_t advance = dwarf_decode_uleb128(p, &br3);
                    p += br3;
                    sm_address += advance * min_insn_length;
                    break;
                }
                case N00B_DW_LNS_advance_line: {
                    size_t  br3;
                    int64_t advance = dwarf_decode_sleb128(p, &br3);
                    p += br3;
                    sm_line = (uint32_t)((int64_t)sm_line + advance);
                    break;
                }
                case N00B_DW_LNS_set_file: {
                    size_t br3;
                    sm_file = (uint32_t)dwarf_decode_uleb128(p, &br3);
                    p += br3;
                    break;
                }
                case N00B_DW_LNS_set_column: {
                    size_t br3;
                    sm_column = (uint16_t)dwarf_decode_uleb128(p, &br3);
                    p += br3;
                    break;
                }
                case N00B_DW_LNS_negate_stmt:
                    sm_is_stmt = !sm_is_stmt;
                    break;

                case N00B_DW_LNS_set_basic_block:
                    break;  // No register change.

                case N00B_DW_LNS_const_add_pc: {
                    uint8_t adjusted = 255 - opcode_base;
                    sm_address += (adjusted / line_range) * min_insn_length;
                    break;
                }
                case N00B_DW_LNS_fixed_advance_pc:
                    if (p + 2 <= unit_end) {
                        uint16_t advance;
                        memcpy(&advance, p, 2);
                        p += 2;
                        sm_address += advance;
                    }
                    break;

                case N00B_DW_LNS_set_prologue_end:
                case N00B_DW_LNS_set_epilogue_begin:
                    break;

                case N00B_DW_LNS_set_isa: {
                    size_t br3;
                    dwarf_decode_uleb128(p, &br3);
                    p += br3;
                    break;
                }
                default:
                    break;
                }
            } else {
                // Special opcode.
                uint8_t adjusted = opcode - opcode_base;
                uint64_t addr_advance =
                    (adjusted / line_range) * min_insn_length;
                int32_t line_advance = line_base + (adjusted % line_range);

                sm_address += addr_advance;
                sm_line = (uint32_t)((int64_t)sm_line + line_advance);

                // Emit row.
                if (entry_count >= entry_cap) {
                    entry_cap *= 2;
                    n00b_dwarf_line_entry_t *ne =
                        n00b_alloc_array(n00b_dwarf_line_entry_t, entry_cap);
                    memcpy(ne, entries, entry_count * sizeof(*ne));
                    entries = ne;
                }
                entries[entry_count].address     = sm_address;
                entries[entry_count].file =
                    (sm_file < file_count) ? files[sm_file] : "";
                entries[entry_count].line        = sm_line;
                entries[entry_count].column       = sm_column;
                entries[entry_count].is_stmt      = sm_is_stmt;
                entries[entry_count].end_sequence = false;
                entry_count++;
            }
        }

skip_program:
        (void)0;
    }

    info->line_entries     = entries;
    info->num_line_entries = entry_count;

    return n00b_result_ok(bool, true);
}

n00b_dwarf_line_entry_t *
n00b_dwarf_line_at_addr(n00b_dwarf_info_t *info, uint64_t addr)
{
    if (!info) {
        return nullptr;
    }
    if (!info->lines_parsed) {
        n00b_result_t(bool) parsed = n00b_dwarf_parse_line_table(info);
        if (n00b_result_is_err(parsed)) {
            return nullptr;
        }
    }

    // Linear scan — find best match (largest address <= addr).
    n00b_dwarf_line_entry_t *best = nullptr;
    for (size_t i = 0; i < info->num_line_entries; i++) {
        n00b_dwarf_line_entry_t *e = &info->line_entries[i];
        if (e->end_sequence) {
            continue;
        }
        if (e->address <= addr) {
            if (!best || e->address > best->address) {
                best = e;
            }
        }
    }
    return best;
}

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "compiler/objfile/dwarf.h"
#include "compiler/objfile/abstract.h"

// ============================================================================
// Helpers: synthetic DWARF data construction
// ============================================================================

static void
put8(uint8_t *p, uint8_t v)
{
    *p = v;
}

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

/// Encode a ULEB128 value into `buf`, return bytes written.
static size_t
encode_uleb128(uint8_t *buf, uint64_t value)
{
    size_t n = 0;
    do {
        uint8_t byte = value & 0x7f;
        value >>= 7;
        if (value != 0) {
            byte |= 0x80;
        }
        buf[n++] = byte;
    } while (value != 0);
    return n;
}

/// Encode a SLEB128 value into `buf`, return bytes written.
static size_t
encode_sleb128(uint8_t *buf, int64_t value)
{
    size_t   n    = 0;
    bool     more = true;
    while (more) {
        uint8_t byte = value & 0x7f;
        value >>= 7;
        if ((value == 0 && !(byte & 0x40)) || (value == -1 && (byte & 0x40))) {
            more = false;
        } else {
            byte |= 0x80;
        }
        buf[n++] = byte;
    }
    return n;
}

// ============================================================================
// Phase 10a tests: constants + types
// ============================================================================

static void
test_dwarf_constants(void)
{
    // Spot-check a selection of key constant values.
    assert(N00B_DW_TAG_compile_unit == 0x11);
    assert(N00B_DW_TAG_subprogram == 0x2e);
    assert(N00B_DW_TAG_variable == 0x34);
    assert(N00B_DW_TAG_base_type == 0x24);
    assert(N00B_DW_TAG_structure_type == 0x13);
    assert(N00B_DW_TAG_formal_parameter == 0x05);
    assert(N00B_DW_TAG_typedef == 0x16);
    assert(N00B_DW_TAG_pointer_type == 0x0f);
    assert(N00B_DW_TAG_enumeration_type == 0x04);
    assert(N00B_DW_TAG_enumerator == 0x28);
    assert(N00B_DW_TAG_member == 0x0d);
    assert(N00B_DW_TAG_array_type == 0x01);
    assert(N00B_DW_TAG_const_type == 0x26);
    assert(N00B_DW_TAG_volatile_type == 0x35);
    assert(N00B_DW_TAG_restrict_type == 0x37);
    assert(N00B_DW_TAG_union_type == 0x17);
    assert(N00B_DW_TAG_subroutine_type == 0x15);

    assert(N00B_DW_AT_name == 0x03);
    assert(N00B_DW_AT_type == 0x49);
    assert(N00B_DW_AT_low_pc == 0x11);
    assert(N00B_DW_AT_high_pc == 0x12);
    assert(N00B_DW_AT_byte_size == 0x0b);
    assert(N00B_DW_AT_encoding == 0x3e);
    assert(N00B_DW_AT_linkage_name == 0x6e);
    assert(N00B_DW_AT_data_member_location == 0x38);
    assert(N00B_DW_AT_str_offsets_base == 0x72);
    assert(N00B_DW_AT_addr_base == 0x73);
    assert(N00B_DW_AT_external == 0x3f);

    assert(N00B_DW_FORM_addr == 0x01);
    assert(N00B_DW_FORM_data1 == 0x0b);
    assert(N00B_DW_FORM_data2 == 0x05);
    assert(N00B_DW_FORM_data4 == 0x06);
    assert(N00B_DW_FORM_data8 == 0x07);
    assert(N00B_DW_FORM_string == 0x08);
    assert(N00B_DW_FORM_strp == 0x0e);
    assert(N00B_DW_FORM_udata == 0x0f);
    assert(N00B_DW_FORM_sdata == 0x0d);
    assert(N00B_DW_FORM_flag_present == 0x19);
    assert(N00B_DW_FORM_exprloc == 0x18);
    assert(N00B_DW_FORM_sec_offset == 0x17);
    assert(N00B_DW_FORM_ref4 == 0x13);
    assert(N00B_DW_FORM_strx == 0x1a);
    assert(N00B_DW_FORM_addrx == 0x1b);
    assert(N00B_DW_FORM_implicit_const == 0x21);

    assert(N00B_DW_ATE_signed == 0x05);
    assert(N00B_DW_ATE_unsigned == 0x07);
    assert(N00B_DW_ATE_boolean == 0x02);
    assert(N00B_DW_ATE_float == 0x04);
    assert(N00B_DW_ATE_UTF == 0x10);

    assert(N00B_DW_UT_compile == 0x01);
    assert(N00B_DW_UT_type == 0x02);
    assert(N00B_DW_UT_skeleton == 0x04);

    assert(N00B_DW_LNS_copy == 0x01);
    assert(N00B_DW_LNS_advance_pc == 0x02);
    assert(N00B_DW_LNS_advance_line == 0x03);
    assert(N00B_DW_LNS_set_file == 0x04);
    assert(N00B_DW_LNS_negate_stmt == 0x06);

    assert(N00B_DW_LNE_end_sequence == 0x01);
    assert(N00B_DW_LNE_set_address == 0x02);
    assert(N00B_DW_LNE_set_discriminator == 0x04);

    assert(N00B_DW_CHILDREN_no == 0x00);
    assert(N00B_DW_CHILDREN_yes == 0x01);

    printf("  [PASS] dwarf_constants\n");
}

static void
test_dwarf_attr_size(void)
{
    // Verify key struct sizes are reasonable (not zero, properly packed).
    assert(sizeof(n00b_dwarf_attr_t) > 0);
    assert(sizeof(n00b_dwarf_die_t) > 0);
    assert(sizeof(n00b_dwarf_cu_t) > 0);
    assert(sizeof(n00b_dwarf_line_entry_t) > 0);
    assert(sizeof(n00b_dwarf_type_def_t) > 0);
    assert(sizeof(n00b_dwarf_function_t) > 0);
    assert(sizeof(n00b_dwarf_info_t) > 0);

    // The attr union should be at least 16 bytes (pointer + size for block).
    assert(sizeof(((n00b_dwarf_attr_t *)0)->u64) == 8);
    assert(sizeof(((n00b_dwarf_attr_t *)0)->s64) == 8);

    // Builder types.
    assert(sizeof(n00b_dwarf_build_attr_t) > 0);
    assert(sizeof(n00b_dwarf_build_die_t) > 0);
    assert(sizeof(n00b_dwarf_builder_t) > 0);
    assert(sizeof(n00b_dwarf_sections_t) > 0);

    printf("  [PASS] dwarf_attr_size\n");
}

static void
test_dwarf_cu_header_size(void)
{
    // CU header struct should have all expected fields.
    n00b_dwarf_cu_t cu = {0};
    cu.version      = 4;
    cu.address_size = 8;
    cu.abbrev_offset = 0;
    cu.is_64bit     = false;
    cu.cu_offset    = 0;

    assert(cu.version == 4);
    assert(cu.address_size == 8);
    assert(cu.is_64bit == false);
    assert(cu.bases_parsed == false);
    assert(cu.str_offsets_base == 0);
    assert(cu.addr_base == 0);

    printf("  [PASS] dwarf_cu_header_size\n");
}

// ============================================================================
// Phase 10b tests: core reader
// ============================================================================

/// Build a minimal .debug_abbrev section with one abbreviation entry:
///   code=1, tag=N00B_DW_TAG_compile_unit, has_children=yes,
///   attrs: [N00B_DW_AT_name/N00B_DW_FORM_strp, N00B_DW_AT_low_pc/N00B_DW_FORM_addr]
/// Followed by the terminating 0 code.
static uint8_t *
make_simple_abbrev(size_t *out_size)
{
    uint8_t buf[128];
    size_t  pos = 0;

    // Abbreviation code = 1
    pos += encode_uleb128(buf + pos, 1);
    // Tag = N00B_DW_TAG_compile_unit
    pos += encode_uleb128(buf + pos, N00B_DW_TAG_compile_unit);
    // Has children = yes
    buf[pos++] = N00B_DW_CHILDREN_yes;

    // Attribute spec: N00B_DW_AT_name, N00B_DW_FORM_strp
    pos += encode_uleb128(buf + pos, N00B_DW_AT_name);
    pos += encode_uleb128(buf + pos, N00B_DW_FORM_strp);
    // Attribute spec: N00B_DW_AT_low_pc, N00B_DW_FORM_addr
    pos += encode_uleb128(buf + pos, N00B_DW_AT_low_pc);
    pos += encode_uleb128(buf + pos, N00B_DW_FORM_addr);
    // End of attr specs
    pos += encode_uleb128(buf + pos, 0);
    pos += encode_uleb128(buf + pos, 0);

    // Abbreviation code = 2: N00B_DW_TAG_subprogram, no children
    pos += encode_uleb128(buf + pos, 2);
    pos += encode_uleb128(buf + pos, N00B_DW_TAG_subprogram);
    buf[pos++] = N00B_DW_CHILDREN_no;

    // Attribute spec: N00B_DW_AT_name, N00B_DW_FORM_string (inline)
    pos += encode_uleb128(buf + pos, N00B_DW_AT_name);
    pos += encode_uleb128(buf + pos, N00B_DW_FORM_string);
    // Attribute spec: N00B_DW_AT_low_pc, N00B_DW_FORM_addr
    pos += encode_uleb128(buf + pos, N00B_DW_AT_low_pc);
    pos += encode_uleb128(buf + pos, N00B_DW_FORM_addr);
    // Attribute spec: N00B_DW_AT_high_pc, N00B_DW_FORM_data4 (offset from low_pc)
    pos += encode_uleb128(buf + pos, N00B_DW_AT_high_pc);
    pos += encode_uleb128(buf + pos, N00B_DW_FORM_data4);
    // End of attr specs
    pos += encode_uleb128(buf + pos, 0);
    pos += encode_uleb128(buf + pos, 0);

    // Terminating 0 code
    buf[pos++] = 0;

    uint8_t *result = n00b_alloc_array(uint8_t, pos);
    memcpy(result, buf, pos);
    *out_size = pos;
    return result;
}

/// Build a minimal DWARF 4 .debug_info section with one CU containing
/// one compile_unit DIE (with a subprogram child).
/// The .debug_str section is also constructed.
static void
make_simple_debug_info(uint8_t **out_info, size_t *out_info_size,
                       uint8_t **out_str,  size_t *out_str_size)
{
    // String table: offset 0 = "", offset 1 = "test.c"
    const char *str_data = "\0test.c";
    size_t      str_size = 8;  // NUL + "test.c" + NUL
    uint8_t    *str      = n00b_alloc_array(uint8_t, str_size);
    memcpy(str, str_data, str_size);

    // Build .debug_info
    uint8_t buf[256];
    size_t  pos = 0;

    // --- CU Header (DWARF 4, 32-bit format) ---
    // unit_length: placeholder, fill later
    size_t unit_length_pos = pos;
    put32(buf + pos, 0);
    pos += 4;
    // version = 4
    put16(buf + pos, 4);
    pos += 2;
    // abbrev_offset = 0
    put32(buf + pos, 0);
    pos += 4;
    // address_size = 8
    buf[pos++] = 8;

    // --- Root DIE: abbrev code 1 (compile_unit) ---
    pos += encode_uleb128(buf + pos, 1);
    // N00B_DW_AT_name: N00B_DW_FORM_strp → offset 1 ("test.c")
    put32(buf + pos, 1);
    pos += 4;
    // N00B_DW_AT_low_pc: N00B_DW_FORM_addr → 0x1000
    put64(buf + pos, 0x1000);
    pos += 8;

    // --- Child DIE: abbrev code 2 (subprogram) ---
    pos += encode_uleb128(buf + pos, 2);
    // N00B_DW_AT_name: N00B_DW_FORM_string → "main\0"
    memcpy(buf + pos, "main\0", 5);
    pos += 5;
    // N00B_DW_AT_low_pc: N00B_DW_FORM_addr → 0x1000
    put64(buf + pos, 0x1000);
    pos += 8;
    // N00B_DW_AT_high_pc: N00B_DW_FORM_data4 → 0x100 (size)
    put32(buf + pos, 0x100);
    pos += 4;

    // Null terminator for children of compile_unit
    buf[pos++] = 0;

    // Patch unit_length (total size after the 4-byte length field)
    uint32_t unit_len = (uint32_t)(pos - unit_length_pos - 4);
    put32(buf + unit_length_pos, unit_len);

    uint8_t *info = n00b_alloc_array(uint8_t, pos);
    memcpy(info, buf, pos);

    *out_info      = info;
    *out_info_size = pos;
    *out_str       = str;
    *out_str_size  = str_size;
}

static void
test_parse_abbrev_table(void)
{
    size_t   abbrev_size;
    uint8_t *abbrev_data = make_simple_abbrev(&abbrev_size);

    n00b_dwarf_abbrev_table_t *table =
        n00b_dwarf_parse_abbrev_table(abbrev_data, abbrev_size, 0);
    assert(table != nullptr);
    assert(table->count == 2);

    // Entry 1: compile_unit with children
    const n00b_dwarf_abbrev_t *e1 = n00b_dwarf_abbrev_find(table, 1);
    assert(e1 != nullptr);
    assert(e1->tag == N00B_DW_TAG_compile_unit);
    assert(e1->has_children == true);
    assert(e1->attr_count == 2);
    assert(e1->attrs[0].name == N00B_DW_AT_name);
    assert(e1->attrs[0].form == N00B_DW_FORM_strp);
    assert(e1->attrs[1].name == N00B_DW_AT_low_pc);
    assert(e1->attrs[1].form == N00B_DW_FORM_addr);

    // Entry 2: subprogram, no children
    const n00b_dwarf_abbrev_t *e2 = n00b_dwarf_abbrev_find(table, 2);
    assert(e2 != nullptr);
    assert(e2->tag == N00B_DW_TAG_subprogram);
    assert(e2->has_children == false);
    assert(e2->attr_count == 3);

    // Non-existent code
    assert(n00b_dwarf_abbrev_find(table, 99) == nullptr);

    printf("  [PASS] parse_abbrev_table\n");
}

static void
test_parse_cu_header_v4(void)
{
    uint8_t *info_data, *str_data;
    size_t   info_size, str_size;
    make_simple_debug_info(&info_data, &info_size, &str_data, &str_size);

    n00b_dwarf_cu_t cu = {0};
    bool ok = n00b_dwarf_parse_cu_header(info_data, info_size, 0, &cu);
    assert(ok);
    assert(cu.version == 4);
    assert(cu.address_size == 8);
    assert(cu.abbrev_offset == 0);
    assert(cu.is_64bit == false);
    assert(cu.cu_offset == 0);
    // DWARF 4 header: 4 (unit_length) + 2 (version) + 4 (abbrev_offset) + 1 (addr_size) = 11
    assert(cu.header_size == 11);
    assert(cu.die_offset == 11);

    printf("  [PASS] parse_cu_header_v4\n");
}

static void
test_parse_cu_header_v5(void)
{
    // Build a DWARF 5 CU header.
    uint8_t buf[64];
    size_t  pos = 0;

    // unit_length (32-bit format)
    put32(buf + pos, 20);  // length of rest (arbitrary, enough for header)
    pos += 4;
    // version = 5
    put16(buf + pos, 5);
    pos += 2;
    // unit_type = N00B_DW_UT_compile
    buf[pos++] = N00B_DW_UT_compile;
    // address_size = 8
    buf[pos++] = 8;
    // abbrev_offset = 0
    put32(buf + pos, 0);
    pos += 4;

    n00b_dwarf_cu_t cu = {0};
    bool ok = n00b_dwarf_parse_cu_header(buf, pos, 0, &cu);
    assert(ok);
    assert(cu.version == 5);
    assert(cu.unit_type == N00B_DW_UT_compile);
    assert(cu.address_size == 8);
    assert(cu.is_64bit == false);
    // DWARF 5 header: 4 + 2 + 1 + 1 + 4 = 12
    assert(cu.header_size == 12);
    assert(cu.die_offset == 12);

    printf("  [PASS] parse_cu_header_v5\n");
}

static void
test_parse_die_simple(void)
{
    size_t   abbrev_size;
    uint8_t *abbrev_data = make_simple_abbrev(&abbrev_size);
    uint8_t *info_data, *str_data;
    size_t   info_size, str_size;
    make_simple_debug_info(&info_data, &info_size, &str_data, &str_size);

    n00b_dwarf_abbrev_table_t *table =
        n00b_dwarf_parse_abbrev_table(abbrev_data, abbrev_size, 0);

    n00b_dwarf_cu_t cu = {0};
    n00b_dwarf_parse_cu_header(info_data, info_size, 0, &cu);

    // Create a minimal info struct for the DIE parser.
    n00b_dwarf_info_t dinfo = {0};
    dinfo.debug_info      = info_data;
    dinfo.debug_info_size = info_size;
    dinfo.debug_str       = str_data;
    dinfo.debug_str_size  = str_size;

    // Parse the root DIE (compile_unit) at die_offset.
    n00b_dwarf_die_t die = {0};
    bool ok = n00b_dwarf_parse_die(&dinfo, table, &cu, cu.die_offset, &die);
    assert(ok);
    assert(die.tag == N00B_DW_TAG_compile_unit);
    assert(die.has_children == true);
    assert(die.attr_count == 2);

    // Check N00B_DW_AT_name → "test.c" (via strp)
    const n00b_dwarf_attr_t *name_attr = n00b_dwarf_die_get_attr(&die, N00B_DW_AT_name);
    assert(name_attr != nullptr);
    assert(name_attr->str != nullptr);
    assert(strcmp(name_attr->str, "test.c") == 0);

    // Check N00B_DW_AT_low_pc → 0x1000
    const n00b_dwarf_attr_t *pc_attr = n00b_dwarf_die_get_attr(&die, N00B_DW_AT_low_pc);
    assert(pc_attr != nullptr);
    assert(pc_attr->u64 == 0x1000);

    printf("  [PASS] parse_die_simple\n");
}

static void
test_parse_attr_forms(void)
{
    // Build a custom abbreviation table and .debug_info to test multiple forms.
    uint8_t abbrev_buf[128];
    size_t  apos = 0;

    // Abbrev 1: N00B_DW_TAG_compile_unit, no children
    // Attrs: data1, data2, data4, data8, udata, sdata, flag_present, string
    apos += encode_uleb128(abbrev_buf + apos, 1);
    apos += encode_uleb128(abbrev_buf + apos, N00B_DW_TAG_compile_unit);
    abbrev_buf[apos++] = N00B_DW_CHILDREN_no;

    apos += encode_uleb128(abbrev_buf + apos, N00B_DW_AT_byte_size);
    apos += encode_uleb128(abbrev_buf + apos, N00B_DW_FORM_data1);

    apos += encode_uleb128(abbrev_buf + apos, N00B_DW_AT_bit_size);
    apos += encode_uleb128(abbrev_buf + apos, N00B_DW_FORM_data2);

    apos += encode_uleb128(abbrev_buf + apos, N00B_DW_AT_encoding);
    apos += encode_uleb128(abbrev_buf + apos, N00B_DW_FORM_data4);

    apos += encode_uleb128(abbrev_buf + apos, N00B_DW_AT_const_value);
    apos += encode_uleb128(abbrev_buf + apos, N00B_DW_FORM_data8);

    apos += encode_uleb128(abbrev_buf + apos, N00B_DW_AT_count);
    apos += encode_uleb128(abbrev_buf + apos, N00B_DW_FORM_udata);

    apos += encode_uleb128(abbrev_buf + apos, N00B_DW_AT_lower_bound);
    apos += encode_uleb128(abbrev_buf + apos, N00B_DW_FORM_sdata);

    apos += encode_uleb128(abbrev_buf + apos, N00B_DW_AT_external);
    apos += encode_uleb128(abbrev_buf + apos, N00B_DW_FORM_flag_present);

    apos += encode_uleb128(abbrev_buf + apos, N00B_DW_AT_name);
    apos += encode_uleb128(abbrev_buf + apos, N00B_DW_FORM_string);

    // End attrs
    apos += encode_uleb128(abbrev_buf + apos, 0);
    apos += encode_uleb128(abbrev_buf + apos, 0);
    // End table
    abbrev_buf[apos++] = 0;

    // Build .debug_info
    uint8_t info_buf[128];
    size_t  ipos = 0;

    // CU header (DWARF 4, 32-bit)
    size_t len_pos = ipos;
    put32(info_buf + ipos, 0);  // placeholder
    ipos += 4;
    put16(info_buf + ipos, 4);
    ipos += 2;
    put32(info_buf + ipos, 0);
    ipos += 4;
    info_buf[ipos++] = 8;  // address_size

    // DIE: abbrev code 1
    ipos += encode_uleb128(info_buf + ipos, 1);
    // data1 → 0x42
    info_buf[ipos++] = 0x42;
    // data2 → 0x1234
    put16(info_buf + ipos, 0x1234);
    ipos += 2;
    // data4 → 0xDEADBEEF
    put32(info_buf + ipos, 0xDEADBEEF);
    ipos += 4;
    // data8 → 0x0102030405060708
    put64(info_buf + ipos, 0x0102030405060708ULL);
    ipos += 8;
    // udata → 300 (encoded as ULEB128)
    ipos += encode_uleb128(info_buf + ipos, 300);
    // sdata → -42 (encoded as SLEB128)
    ipos += encode_sleb128(info_buf + ipos, -42);
    // flag_present → no data (implicit true)
    // string → "hello\0"
    memcpy(info_buf + ipos, "hello\0", 6);
    ipos += 6;

    // Patch unit_length
    put32(info_buf + len_pos, (uint32_t)(ipos - len_pos - 4));

    n00b_dwarf_abbrev_table_t *table =
        n00b_dwarf_parse_abbrev_table(abbrev_buf, apos, 0);
    assert(table != nullptr);

    n00b_dwarf_cu_t cu = {0};
    n00b_dwarf_parse_cu_header(info_buf, ipos, 0, &cu);

    n00b_dwarf_info_t dinfo = {0};
    dinfo.debug_info      = info_buf;
    dinfo.debug_info_size = ipos;

    n00b_dwarf_die_t die = {0};
    bool ok = n00b_dwarf_parse_die(&dinfo, table, &cu, cu.die_offset, &die);
    assert(ok);
    assert(die.attr_count == 8);

    // data1
    const n00b_dwarf_attr_t *a = n00b_dwarf_die_get_attr(&die, N00B_DW_AT_byte_size);
    assert(a && a->u64 == 0x42);
    // data2
    a = n00b_dwarf_die_get_attr(&die, N00B_DW_AT_bit_size);
    assert(a && a->u64 == 0x1234);
    // data4
    a = n00b_dwarf_die_get_attr(&die, N00B_DW_AT_encoding);
    assert(a && a->u64 == 0xDEADBEEF);
    // data8
    a = n00b_dwarf_die_get_attr(&die, N00B_DW_AT_const_value);
    assert(a && a->u64 == 0x0102030405060708ULL);
    // udata
    a = n00b_dwarf_die_get_attr(&die, N00B_DW_AT_count);
    assert(a && a->u64 == 300);
    // sdata
    a = n00b_dwarf_die_get_attr(&die, N00B_DW_AT_lower_bound);
    assert(a && a->s64 == -42);
    // flag_present
    a = n00b_dwarf_die_get_attr(&die, N00B_DW_AT_external);
    assert(a && a->u64 == 1);
    // string
    a = n00b_dwarf_die_get_attr(&die, N00B_DW_AT_name);
    assert(a && a->str != nullptr && strcmp(a->str, "hello") == 0);

    printf("  [PASS] parse_attr_forms\n");
}

static void
test_skip_die(void)
{
    size_t   abbrev_size;
    uint8_t *abbrev_data = make_simple_abbrev(&abbrev_size);
    uint8_t *info_data, *str_data;
    size_t   info_size, str_size;
    make_simple_debug_info(&info_data, &info_size, &str_data, &str_size);

    n00b_dwarf_abbrev_table_t *table =
        n00b_dwarf_parse_abbrev_table(abbrev_data, abbrev_size, 0);

    n00b_dwarf_cu_t cu = {0};
    n00b_dwarf_parse_cu_header(info_data, info_size, 0, &cu);

    n00b_dwarf_info_t dinfo = {0};
    dinfo.debug_info      = info_data;
    dinfo.debug_info_size = info_size;
    dinfo.debug_str       = str_data;
    dinfo.debug_str_size  = str_size;

    // Skip the root DIE (compile_unit) — should land at the child (subprogram).
    size_t next = n00b_dwarf_skip_die(&dinfo, table, &cu, cu.die_offset);
    assert(next > cu.die_offset);
    assert(next < info_size);

    // Parse what's at 'next' — should be the subprogram DIE.
    n00b_dwarf_die_t die = {0};
    bool ok = n00b_dwarf_parse_die(&dinfo, table, &cu, next, &die);
    assert(ok);
    assert(die.tag == N00B_DW_TAG_subprogram);

    printf("  [PASS] skip_die\n");
}

static void
test_multi_cu(void)
{
    // Build two CUs back-to-back in .debug_info.
    size_t   abbrev_size;
    uint8_t *abbrev_data = make_simple_abbrev(&abbrev_size);

    // String table
    const char *str_bytes = "\0cu1.c\0cu2.c";
    size_t str_size = 13;  // NUL + "cu1.c" + NUL + "cu2.c" + NUL
    uint8_t *str_data = n00b_alloc_array(uint8_t, str_size);
    memcpy(str_data, str_bytes, str_size);

    uint8_t buf[256];
    size_t  pos = 0;

    // --- CU 1 ---
    size_t cu1_start = pos;
    size_t len1_pos  = pos;
    put32(buf + pos, 0);
    pos += 4;
    put16(buf + pos, 4);
    pos += 2;
    put32(buf + pos, 0);
    pos += 4;
    buf[pos++] = 8;
    // Root DIE: abbrev 1 (compile_unit)
    pos += encode_uleb128(buf + pos, 1);
    put32(buf + pos, 1);  // N00B_DW_AT_name → strp offset 1 ("cu1.c")
    pos += 4;
    put64(buf + pos, 0x1000);  // N00B_DW_AT_low_pc
    pos += 8;
    // Null child terminator
    buf[pos++] = 0;
    put32(buf + len1_pos, (uint32_t)(pos - cu1_start - 4));

    // --- CU 2 ---
    size_t cu2_start = pos;
    size_t len2_pos  = pos;
    put32(buf + pos, 0);
    pos += 4;
    put16(buf + pos, 4);
    pos += 2;
    put32(buf + pos, 0);
    pos += 4;
    buf[pos++] = 8;
    // Root DIE: abbrev 1 (compile_unit)
    pos += encode_uleb128(buf + pos, 1);
    put32(buf + pos, 7);  // N00B_DW_AT_name → strp offset 7 ("cu2.c")
    pos += 4;
    put64(buf + pos, 0x2000);  // N00B_DW_AT_low_pc
    pos += 8;
    // Null child terminator
    buf[pos++] = 0;
    put32(buf + len2_pos, (uint32_t)(pos - cu2_start - 4));

    // Parse using n00b_dwarf_parse_sections
    n00b_result_t(n00b_dwarf_info_t *) r =
        n00b_dwarf_parse_sections(buf, pos,
                                  abbrev_data, abbrev_size,
                                  str_data, str_size,
                                  nullptr, 0);
    assert(n00b_result_is_ok(r));
    n00b_dwarf_info_t *info = n00b_result_get(r);
    assert(info != nullptr);
    assert(info->num_cus == 2);
    assert(info->cus[0].version == 4);
    assert(info->cus[0].cu_offset == cu1_start);
    assert(info->cus[1].version == 4);
    assert(info->cus[1].cu_offset == cu2_start);

    printf("  [PASS] multi_cu\n");
}

static void
test_empty_debug_info(void)
{
    // Empty .debug_info → 0 CUs, no error.
    n00b_result_t(n00b_dwarf_info_t *) r =
        n00b_dwarf_parse_sections(nullptr, 0,
                                  nullptr, 0,
                                  nullptr, 0,
                                  nullptr, 0);
    assert(n00b_result_is_ok(r));
    n00b_dwarf_info_t *info = n00b_result_get(r);
    assert(info != nullptr);
    assert(info->num_cus == 0);

    printf("  [PASS] empty_debug_info\n");
}

// ============================================================================
// Phase 10c tests: function + type indexing + query
// ============================================================================

/// Build DWARF with a subprogram and struct type for query testing.
/// Abbrev table:
///   1: N00B_DW_TAG_compile_unit (has_children) — N00B_DW_AT_name/strp, N00B_DW_AT_low_pc/addr
///   2: N00B_DW_TAG_subprogram (no children) — N00B_DW_AT_name/string, N00B_DW_AT_low_pc/addr,
///      N00B_DW_AT_high_pc/data4
///   3: N00B_DW_TAG_base_type (no children) — N00B_DW_AT_name/string, N00B_DW_AT_byte_size/data1,
///      N00B_DW_AT_encoding/data1
///   4: N00B_DW_TAG_structure_type (has_children) — N00B_DW_AT_name/string,
///      N00B_DW_AT_byte_size/data1
///   5: N00B_DW_TAG_member (no children) — N00B_DW_AT_name/string,
///      N00B_DW_AT_data_member_location/data1
///   6: N00B_DW_TAG_enumeration_type (has_children) — N00B_DW_AT_name/string,
///      N00B_DW_AT_byte_size/data1
///   7: N00B_DW_TAG_enumerator (no children) — N00B_DW_AT_name/string,
///      N00B_DW_AT_const_value/sdata
///   8: N00B_DW_TAG_typedef (no children) — N00B_DW_AT_name/string
static void
make_rich_debug_data(uint8_t **out_abbrev, size_t *out_abbrev_size,
                     uint8_t **out_info,   size_t *out_info_size,
                     uint8_t **out_str,    size_t *out_str_size)
{
    // Abbrev table
    uint8_t abuf[512];
    size_t  apos = 0;

    // Abbrev 1: compile_unit
    apos += encode_uleb128(abuf + apos, 1);
    apos += encode_uleb128(abuf + apos, N00B_DW_TAG_compile_unit);
    abuf[apos++] = N00B_DW_CHILDREN_yes;
    apos += encode_uleb128(abuf + apos, N00B_DW_AT_name);
    apos += encode_uleb128(abuf + apos, N00B_DW_FORM_strp);
    apos += encode_uleb128(abuf + apos, N00B_DW_AT_low_pc);
    apos += encode_uleb128(abuf + apos, N00B_DW_FORM_addr);
    apos += encode_uleb128(abuf + apos, 0);
    apos += encode_uleb128(abuf + apos, 0);

    // Abbrev 2: subprogram
    apos += encode_uleb128(abuf + apos, 2);
    apos += encode_uleb128(abuf + apos, N00B_DW_TAG_subprogram);
    abuf[apos++] = N00B_DW_CHILDREN_no;
    apos += encode_uleb128(abuf + apos, N00B_DW_AT_name);
    apos += encode_uleb128(abuf + apos, N00B_DW_FORM_string);
    apos += encode_uleb128(abuf + apos, N00B_DW_AT_low_pc);
    apos += encode_uleb128(abuf + apos, N00B_DW_FORM_addr);
    apos += encode_uleb128(abuf + apos, N00B_DW_AT_high_pc);
    apos += encode_uleb128(abuf + apos, N00B_DW_FORM_data4);
    apos += encode_uleb128(abuf + apos, 0);
    apos += encode_uleb128(abuf + apos, 0);

    // Abbrev 3: base_type
    apos += encode_uleb128(abuf + apos, 3);
    apos += encode_uleb128(abuf + apos, N00B_DW_TAG_base_type);
    abuf[apos++] = N00B_DW_CHILDREN_no;
    apos += encode_uleb128(abuf + apos, N00B_DW_AT_name);
    apos += encode_uleb128(abuf + apos, N00B_DW_FORM_string);
    apos += encode_uleb128(abuf + apos, N00B_DW_AT_byte_size);
    apos += encode_uleb128(abuf + apos, N00B_DW_FORM_data1);
    apos += encode_uleb128(abuf + apos, N00B_DW_AT_encoding);
    apos += encode_uleb128(abuf + apos, N00B_DW_FORM_data1);
    apos += encode_uleb128(abuf + apos, 0);
    apos += encode_uleb128(abuf + apos, 0);

    // Abbrev 4: structure_type (has children for members)
    apos += encode_uleb128(abuf + apos, 4);
    apos += encode_uleb128(abuf + apos, N00B_DW_TAG_structure_type);
    abuf[apos++] = N00B_DW_CHILDREN_yes;
    apos += encode_uleb128(abuf + apos, N00B_DW_AT_name);
    apos += encode_uleb128(abuf + apos, N00B_DW_FORM_string);
    apos += encode_uleb128(abuf + apos, N00B_DW_AT_byte_size);
    apos += encode_uleb128(abuf + apos, N00B_DW_FORM_data1);
    apos += encode_uleb128(abuf + apos, 0);
    apos += encode_uleb128(abuf + apos, 0);

    // Abbrev 5: member
    apos += encode_uleb128(abuf + apos, 5);
    apos += encode_uleb128(abuf + apos, N00B_DW_TAG_member);
    abuf[apos++] = N00B_DW_CHILDREN_no;
    apos += encode_uleb128(abuf + apos, N00B_DW_AT_name);
    apos += encode_uleb128(abuf + apos, N00B_DW_FORM_string);
    apos += encode_uleb128(abuf + apos, N00B_DW_AT_data_member_location);
    apos += encode_uleb128(abuf + apos, N00B_DW_FORM_data1);
    apos += encode_uleb128(abuf + apos, 0);
    apos += encode_uleb128(abuf + apos, 0);

    // Abbrev 6: enumeration_type (has children for enumerators)
    apos += encode_uleb128(abuf + apos, 6);
    apos += encode_uleb128(abuf + apos, N00B_DW_TAG_enumeration_type);
    abuf[apos++] = N00B_DW_CHILDREN_yes;
    apos += encode_uleb128(abuf + apos, N00B_DW_AT_name);
    apos += encode_uleb128(abuf + apos, N00B_DW_FORM_string);
    apos += encode_uleb128(abuf + apos, N00B_DW_AT_byte_size);
    apos += encode_uleb128(abuf + apos, N00B_DW_FORM_data1);
    apos += encode_uleb128(abuf + apos, 0);
    apos += encode_uleb128(abuf + apos, 0);

    // Abbrev 7: enumerator
    apos += encode_uleb128(abuf + apos, 7);
    apos += encode_uleb128(abuf + apos, N00B_DW_TAG_enumerator);
    abuf[apos++] = N00B_DW_CHILDREN_no;
    apos += encode_uleb128(abuf + apos, N00B_DW_AT_name);
    apos += encode_uleb128(abuf + apos, N00B_DW_FORM_string);
    apos += encode_uleb128(abuf + apos, N00B_DW_AT_const_value);
    apos += encode_uleb128(abuf + apos, N00B_DW_FORM_sdata);
    apos += encode_uleb128(abuf + apos, 0);
    apos += encode_uleb128(abuf + apos, 0);

    // Abbrev 8: typedef
    apos += encode_uleb128(abuf + apos, 8);
    apos += encode_uleb128(abuf + apos, N00B_DW_TAG_typedef);
    abuf[apos++] = N00B_DW_CHILDREN_no;
    apos += encode_uleb128(abuf + apos, N00B_DW_AT_name);
    apos += encode_uleb128(abuf + apos, N00B_DW_FORM_string);
    apos += encode_uleb128(abuf + apos, 0);
    apos += encode_uleb128(abuf + apos, 0);

    // End of table
    abuf[apos++] = 0;

    uint8_t *abbrev = n00b_alloc_array(uint8_t, apos);
    memcpy(abbrev, abuf, apos);
    *out_abbrev      = abbrev;
    *out_abbrev_size = apos;

    // String table: offset 0 = "", offset 1 = "rich.c"
    const char *str_data = "\0rich.c";
    size_t      str_size = 8;
    uint8_t    *str      = n00b_alloc_array(uint8_t, str_size);
    memcpy(str, str_data, str_size);
    *out_str      = str;
    *out_str_size = str_size;

    // Build .debug_info
    uint8_t ibuf[512];
    size_t  ipos = 0;

    // CU header (DWARF 4, 32-bit)
    size_t len_pos = ipos;
    put32(ibuf + ipos, 0);  // placeholder
    ipos += 4;
    put16(ibuf + ipos, 4);  // version
    ipos += 2;
    put32(ibuf + ipos, 0);  // abbrev_offset
    ipos += 4;
    ibuf[ipos++] = 8;       // address_size

    // Root DIE: compile_unit (abbrev 1)
    ipos += encode_uleb128(ibuf + ipos, 1);
    put32(ibuf + ipos, 1);  // N00B_DW_AT_name strp → "rich.c"
    ipos += 4;
    put64(ibuf + ipos, 0x2000);  // N00B_DW_AT_low_pc
    ipos += 8;

    // Child: subprogram "my_func" at 0x2000-0x2080 (abbrev 2)
    ipos += encode_uleb128(ibuf + ipos, 2);
    memcpy(ibuf + ipos, "my_func\0", 8);
    ipos += 8;
    put64(ibuf + ipos, 0x2000);  // low_pc
    ipos += 8;
    put32(ibuf + ipos, 0x80);    // high_pc (size)
    ipos += 4;

    // Child: subprogram "helper" at 0x2100-0x2140 (abbrev 2)
    ipos += encode_uleb128(ibuf + ipos, 2);
    memcpy(ibuf + ipos, "helper\0", 7);
    ipos += 7;
    put64(ibuf + ipos, 0x2100);
    ipos += 8;
    put32(ibuf + ipos, 0x40);
    ipos += 4;

    // Child: base_type "int" (abbrev 3)
    ipos += encode_uleb128(ibuf + ipos, 3);
    memcpy(ibuf + ipos, "int\0", 4);
    ipos += 4;
    ibuf[ipos++] = 4;  // byte_size
    ibuf[ipos++] = N00B_DW_ATE_signed;  // encoding

    // Child: structure_type "point" with 2 members (abbrev 4)
    ipos += encode_uleb128(ibuf + ipos, 4);
    memcpy(ibuf + ipos, "point\0", 6);
    ipos += 6;
    ibuf[ipos++] = 8;  // byte_size

    // member "x" at offset 0 (abbrev 5)
    ipos += encode_uleb128(ibuf + ipos, 5);
    memcpy(ibuf + ipos, "x\0", 2);
    ipos += 2;
    ibuf[ipos++] = 0;  // data_member_location

    // member "y" at offset 4 (abbrev 5)
    ipos += encode_uleb128(ibuf + ipos, 5);
    memcpy(ibuf + ipos, "y\0", 2);
    ipos += 2;
    ibuf[ipos++] = 4;  // data_member_location

    // Null terminator for struct children
    ibuf[ipos++] = 0;

    // Child: enumeration_type "color" (abbrev 6)
    ipos += encode_uleb128(ibuf + ipos, 6);
    memcpy(ibuf + ipos, "color\0", 6);
    ipos += 6;
    ibuf[ipos++] = 4;  // byte_size

    // enumerator RED=0 (abbrev 7)
    ipos += encode_uleb128(ibuf + ipos, 7);
    memcpy(ibuf + ipos, "RED\0", 4);
    ipos += 4;
    ipos += encode_sleb128(ibuf + ipos, 0);

    // enumerator GREEN=1 (abbrev 7)
    ipos += encode_uleb128(ibuf + ipos, 7);
    memcpy(ibuf + ipos, "GREEN\0", 6);
    ipos += 6;
    ipos += encode_sleb128(ibuf + ipos, 1);

    // enumerator BLUE=2 (abbrev 7)
    ipos += encode_uleb128(ibuf + ipos, 7);
    memcpy(ibuf + ipos, "BLUE\0", 5);
    ipos += 5;
    ipos += encode_sleb128(ibuf + ipos, 2);

    // Null terminator for enum children
    ibuf[ipos++] = 0;

    // Child: typedef "my_int" (abbrev 8)
    ipos += encode_uleb128(ibuf + ipos, 8);
    memcpy(ibuf + ipos, "my_int\0", 7);
    ipos += 7;

    // Null terminator for compile_unit children
    ibuf[ipos++] = 0;

    // Patch unit_length
    put32(ibuf + len_pos, (uint32_t)(ipos - len_pos - 4));

    uint8_t *info = n00b_alloc_array(uint8_t, ipos);
    memcpy(info, ibuf, ipos);
    *out_info      = info;
    *out_info_size = ipos;
}

static void
test_func_index_build(void)
{
    uint8_t *abbrev, *info, *str;
    size_t   abbrev_size, info_size, str_size;
    make_rich_debug_data(&abbrev, &abbrev_size, &info, &info_size, &str, &str_size);

    n00b_result_t(n00b_dwarf_info_t *) r =
        n00b_dwarf_parse_sections(info, info_size,
                                  abbrev, abbrev_size,
                                  str, str_size,
                                  nullptr, 0);
    assert(n00b_result_is_ok(r));
    n00b_dwarf_info_t *dw = n00b_result_get(r);

    n00b_dwarf_build_func_index(dw);
    assert(dw->func_index_built == true);
    assert(dw->num_functions >= 2);

    printf("  [PASS] func_index_build\n");
}

static void
test_func_at_addr(void)
{
    uint8_t *abbrev, *info, *str;
    size_t   abbrev_size, info_size, str_size;
    make_rich_debug_data(&abbrev, &abbrev_size, &info, &info_size, &str, &str_size);

    n00b_result_t(n00b_dwarf_info_t *) r =
        n00b_dwarf_parse_sections(info, info_size,
                                  abbrev, abbrev_size,
                                  str, str_size,
                                  nullptr, 0);
    assert(n00b_result_is_ok(r));
    n00b_dwarf_info_t *dw = n00b_result_get(r);

    // Should find my_func at 0x2000
    n00b_dwarf_function_t *f = n00b_dwarf_function_at_addr(dw, 0x2000);
    assert(f != nullptr);
    assert(f->name != nullptr);
    assert(strcmp(f->name->data, "my_func") == 0);

    // Should find my_func at 0x2050 (within range)
    f = n00b_dwarf_function_at_addr(dw, 0x2050);
    assert(f != nullptr);
    assert(strcmp(f->name->data, "my_func") == 0);

    // Should find helper at 0x2100
    f = n00b_dwarf_function_at_addr(dw, 0x2100);
    assert(f != nullptr);
    assert(strcmp(f->name->data, "helper") == 0);

    // Should NOT find anything at 0x3000
    f = n00b_dwarf_function_at_addr(dw, 0x3000);
    assert(f == nullptr);

    printf("  [PASS] func_at_addr\n");
}

static void
test_func_by_name(void)
{
    uint8_t *abbrev, *info, *str;
    size_t   abbrev_size, info_size, str_size;
    make_rich_debug_data(&abbrev, &abbrev_size, &info, &info_size, &str, &str_size);

    n00b_result_t(n00b_dwarf_info_t *) r =
        n00b_dwarf_parse_sections(info, info_size,
                                  abbrev, abbrev_size,
                                  str, str_size,
                                  nullptr, 0);
    assert(n00b_result_is_ok(r));
    n00b_dwarf_info_t *dw = n00b_result_get(r);

    n00b_dwarf_function_t *f = n00b_dwarf_function_by_name(dw, "my_func");
    assert(f != nullptr);
    assert(f->low_pc == 0x2000);

    f = n00b_dwarf_function_by_name(dw, "helper");
    assert(f != nullptr);
    assert(f->low_pc == 0x2100);

    f = n00b_dwarf_function_by_name(dw, "nonexistent");
    assert(f == nullptr);

    printf("  [PASS] func_by_name\n");
}

static void
test_type_struct(void)
{
    uint8_t *abbrev, *info, *str;
    size_t   abbrev_size, info_size, str_size;
    make_rich_debug_data(&abbrev, &abbrev_size, &info, &info_size, &str, &str_size);

    n00b_result_t(n00b_dwarf_info_t *) r =
        n00b_dwarf_parse_sections(info, info_size,
                                  abbrev, abbrev_size,
                                  str, str_size,
                                  nullptr, 0);
    assert(n00b_result_is_ok(r));
    n00b_dwarf_info_t *dw = n00b_result_get(r);

    n00b_dwarf_type_def_t *t = n00b_dwarf_type_by_name(dw, "point");
    assert(t != nullptr);
    assert(t->kind == N00B_DWARF_TYPE_STRUCT);
    assert(t->name != nullptr);
    assert(strcmp(t->name->data, "point") == 0);
    assert(t->byte_size == 8);
    assert(t->num_members == 2);
    assert(strcmp(t->members[0].name->data, "x") == 0);
    assert(t->members[0].offset == 0);
    assert(strcmp(t->members[1].name->data, "y") == 0);
    assert(t->members[1].offset == 4);

    printf("  [PASS] type_struct\n");
}

static void
test_type_enum(void)
{
    uint8_t *abbrev, *info, *str;
    size_t   abbrev_size, info_size, str_size;
    make_rich_debug_data(&abbrev, &abbrev_size, &info, &info_size, &str, &str_size);

    n00b_result_t(n00b_dwarf_info_t *) r =
        n00b_dwarf_parse_sections(info, info_size,
                                  abbrev, abbrev_size,
                                  str, str_size,
                                  nullptr, 0);
    assert(n00b_result_is_ok(r));
    n00b_dwarf_info_t *dw = n00b_result_get(r);

    n00b_dwarf_type_def_t *t = n00b_dwarf_type_by_name(dw, "color");
    assert(t != nullptr);
    assert(t->kind == N00B_DWARF_TYPE_ENUM);
    assert(t->byte_size == 4);
    assert(t->num_enumerators == 3);
    assert(strcmp(t->enumerators[0].name->data, "RED") == 0);
    assert(t->enumerators[0].value == 0);
    assert(strcmp(t->enumerators[1].name->data, "GREEN") == 0);
    assert(t->enumerators[1].value == 1);
    assert(strcmp(t->enumerators[2].name->data, "BLUE") == 0);
    assert(t->enumerators[2].value == 2);

    printf("  [PASS] type_enum\n");
}

static void
test_type_typedef(void)
{
    uint8_t *abbrev, *info, *str;
    size_t   abbrev_size, info_size, str_size;
    make_rich_debug_data(&abbrev, &abbrev_size, &info, &info_size, &str, &str_size);

    n00b_result_t(n00b_dwarf_info_t *) r =
        n00b_dwarf_parse_sections(info, info_size,
                                  abbrev, abbrev_size,
                                  str, str_size,
                                  nullptr, 0);
    assert(n00b_result_is_ok(r));
    n00b_dwarf_info_t *dw = n00b_result_get(r);

    n00b_dwarf_type_def_t *t = n00b_dwarf_type_by_name(dw, "my_int");
    assert(t != nullptr);
    assert(t->kind == N00B_DWARF_TYPE_TYPEDEF);
    assert(strcmp(t->name->data, "my_int") == 0);

    printf("  [PASS] type_typedef\n");
}

// ============================================================================
// Phase 10d tests: code generation
// ============================================================================

static void
test_codegen_struct(void)
{
    // Manually construct a type_def for code generation.
    n00b_dwarf_member_t members[2];
    members[0].name      = n00b_string_from_cstr("x");
    members[0].type_name = n00b_string_from_cstr("int");
    members[0].offset    = 0;
    members[0].size      = 4;
    members[0].bit_size  = 0;
    members[1].name      = n00b_string_from_cstr("y");
    members[1].type_name = n00b_string_from_cstr("int");
    members[1].offset    = 4;
    members[1].size      = 4;
    members[1].bit_size  = 0;

    n00b_dwarf_type_def_t td = {0};
    td.kind        = N00B_DWARF_TYPE_STRUCT;
    td.name        = n00b_string_from_cstr("point");
    td.byte_size   = 8;
    td.alignment   = 4;
    td.members     = members;
    td.num_members = 2;

    n00b_string_t *s = n00b_dwarf_generate_struct(&td);
    assert(s != nullptr);
    assert(strstr(s->data, "struct point {") != nullptr);
    assert(strstr(s->data, "int x;") != nullptr);
    assert(strstr(s->data, "int y;") != nullptr);
    assert(strstr(s->data, "offset: 0") != nullptr);
    assert(strstr(s->data, "offset: 4") != nullptr);
    assert(strstr(s->data, "size: 8") != nullptr);

    printf("  [PASS] codegen_struct\n");
}

static void
test_codegen_enum(void)
{
    n00b_dwarf_enumerator_t enums[3];
    enums[0].name  = n00b_string_from_cstr("RED");
    enums[0].value = 0;
    enums[1].name  = n00b_string_from_cstr("GREEN");
    enums[1].value = 1;
    enums[2].name  = n00b_string_from_cstr("BLUE");
    enums[2].value = 2;

    n00b_dwarf_type_def_t td = {0};
    td.kind            = N00B_DWARF_TYPE_ENUM;
    td.name            = n00b_string_from_cstr("color");
    td.enumerators     = enums;
    td.num_enumerators = 3;

    n00b_string_t *s = n00b_dwarf_generate_enum(&td);
    assert(s != nullptr);
    assert(strstr(s->data, "enum color {") != nullptr);
    assert(strstr(s->data, "RED = 0") != nullptr);
    assert(strstr(s->data, "GREEN = 1") != nullptr);
    assert(strstr(s->data, "BLUE = 2") != nullptr);

    printf("  [PASS] codegen_enum\n");
}

static void
test_codegen_typedef(void)
{
    n00b_dwarf_type_def_t td = {0};
    td.kind         = N00B_DWARF_TYPE_TYPEDEF;
    td.name         = n00b_string_from_cstr("my_int");
    td.aliased_type = n00b_string_from_cstr("int");

    n00b_string_t *s = n00b_dwarf_generate_typedef(&td);
    assert(s != nullptr);
    assert(strstr(s->data, "typedef int my_int;") != nullptr);

    printf("  [PASS] codegen_typedef\n");
}

static void
test_codegen_null(void)
{
    // Null input returns empty string.
    n00b_string_t *s = n00b_dwarf_generate_struct(nullptr);
    assert(s != nullptr);
    assert(s->data[0] == '\0' || strlen(s->data) == 0);

    s = n00b_dwarf_generate_enum(nullptr);
    assert(s != nullptr);

    s = n00b_dwarf_generate_typedef(nullptr);
    assert(s != nullptr);

    printf("  [PASS] codegen_null\n");
}

// ============================================================================
// Phase 10f tests: DWARF builder
// ============================================================================

static void
test_build_empty_cu(void)
{
    n00b_dwarf_builder_t *builder = n00b_dwarf_builder_new();
    assert(builder != nullptr);

    n00b_dwarf_build_cu_t *cu = n00b_dwarf_builder_add_cu(builder, 8);
    assert(cu != nullptr);
    assert(cu->address_size == 8);

    n00b_dwarf_sections_t secs = n00b_dwarf_build(builder);
    assert(secs.debug_info != nullptr);
    assert(secs.debug_abbrev != nullptr);
    assert(secs.debug_str != nullptr);
    assert(n00b_buffer_len(secs.debug_info) > 0);
    assert(n00b_buffer_len(secs.debug_abbrev) > 0);

    printf("  [PASS] build_empty_cu\n");
}

static void
test_build_simple_subprogram(void)
{
    n00b_dwarf_builder_t *builder = n00b_dwarf_builder_new();
    n00b_dwarf_build_cu_t *cu = n00b_dwarf_builder_add_cu(builder, 8);

    // The root DIE is the compile_unit — add attrs to it.
    n00b_dwarf_build_die_add_attr_str(&cu->root, N00B_DW_AT_name, "test.c");
    n00b_dwarf_build_die_add_attr_addr(&cu->root, N00B_DW_AT_low_pc, 0x4000);

    // Add a subprogram child.
    n00b_dwarf_build_die_t *sub = n00b_dwarf_build_die_new(N00B_DW_TAG_subprogram);
    n00b_dwarf_build_die_add_attr_str(sub, N00B_DW_AT_name, "compute");
    n00b_dwarf_build_die_add_attr_addr(sub, N00B_DW_AT_low_pc, 0x4000);
    n00b_dwarf_build_die_add_attr_u64(sub, N00B_DW_AT_high_pc, N00B_DW_FORM_data4, 0x80);
    n00b_dwarf_build_die_add_child(&cu->root, sub);

    n00b_dwarf_sections_t secs = n00b_dwarf_build(builder);
    assert(secs.debug_info != nullptr);
    assert(n00b_buffer_len(secs.debug_info) > 11);  // Must be bigger than just the header.

    printf("  [PASS] build_simple_subprogram\n");
}

static void
test_build_roundtrip(void)
{
    // Build → serialize → parse → verify.
    n00b_dwarf_builder_t *builder = n00b_dwarf_builder_new();
    n00b_dwarf_build_cu_t *cu = n00b_dwarf_builder_add_cu(builder, 8);

    n00b_dwarf_build_die_add_attr_str(&cu->root, N00B_DW_AT_name, "roundtrip.c");
    n00b_dwarf_build_die_add_attr_addr(&cu->root, N00B_DW_AT_low_pc, 0x5000);

    n00b_dwarf_build_die_t *sub = n00b_dwarf_build_die_new(N00B_DW_TAG_subprogram);
    n00b_dwarf_build_die_add_attr_str(sub, N00B_DW_AT_name, "round_func");
    n00b_dwarf_build_die_add_attr_addr(sub, N00B_DW_AT_low_pc, 0x5000);
    n00b_dwarf_build_die_add_attr_u64(sub, N00B_DW_AT_high_pc, N00B_DW_FORM_data4, 0x100);
    n00b_dwarf_build_die_add_child(&cu->root, sub);

    n00b_dwarf_sections_t secs = n00b_dwarf_build(builder);

    // Now parse the output.
    n00b_result_t(n00b_dwarf_info_t *) r =
        n00b_dwarf_parse_sections(
            (const uint8_t *)secs.debug_info->data,
            n00b_buffer_len(secs.debug_info),
            (const uint8_t *)secs.debug_abbrev->data,
            n00b_buffer_len(secs.debug_abbrev),
            (const uint8_t *)secs.debug_str->data,
            n00b_buffer_len(secs.debug_str),
            nullptr, 0);

    assert(n00b_result_is_ok(r));
    n00b_dwarf_info_t *dw = n00b_result_get(r);
    assert(dw->num_cus == 1);
    assert(dw->cus[0].version == 4);
    assert(dw->cus[0].address_size == 8);

    // Verify we can find the function.
    n00b_dwarf_function_t *f = n00b_dwarf_function_by_name(dw, "round_func");
    assert(f != nullptr);
    assert(f->low_pc == 0x5000);
    assert(f->high_pc == 0x5100);

    printf("  [PASS] build_roundtrip\n");
}

static void
test_build_multi_cu(void)
{
    n00b_dwarf_builder_t *builder = n00b_dwarf_builder_new();

    // Two CUs.
    n00b_dwarf_build_cu_t *cu1 = n00b_dwarf_builder_add_cu(builder, 8);
    n00b_dwarf_build_die_add_attr_str(&cu1->root, N00B_DW_AT_name, "file1.c");

    n00b_dwarf_build_cu_t *cu2 = n00b_dwarf_builder_add_cu(builder, 8);
    n00b_dwarf_build_die_add_attr_str(&cu2->root, N00B_DW_AT_name, "file2.c");

    n00b_dwarf_sections_t secs = n00b_dwarf_build(builder);

    n00b_result_t(n00b_dwarf_info_t *) r =
        n00b_dwarf_parse_sections(
            (const uint8_t *)secs.debug_info->data,
            n00b_buffer_len(secs.debug_info),
            (const uint8_t *)secs.debug_abbrev->data,
            n00b_buffer_len(secs.debug_abbrev),
            (const uint8_t *)secs.debug_str->data,
            n00b_buffer_len(secs.debug_str),
            nullptr, 0);

    assert(n00b_result_is_ok(r));
    n00b_dwarf_info_t *dw = n00b_result_get(r);
    assert(dw->num_cus == 2);

    printf("  [PASS] build_multi_cu\n");
}

static void
test_build_nested_children(void)
{
    n00b_dwarf_builder_t *builder = n00b_dwarf_builder_new();
    n00b_dwarf_build_cu_t *cu = n00b_dwarf_builder_add_cu(builder, 8);

    // struct with 2 members
    n00b_dwarf_build_die_t *struc = n00b_dwarf_build_die_new(N00B_DW_TAG_structure_type);
    n00b_dwarf_build_die_add_attr_str(struc, N00B_DW_AT_name, "nested_s");
    n00b_dwarf_build_die_add_attr_u64(struc, N00B_DW_AT_byte_size, N00B_DW_FORM_data1, 16);

    n00b_dwarf_build_die_t *m1 = n00b_dwarf_build_die_new(N00B_DW_TAG_member);
    n00b_dwarf_build_die_add_attr_str(m1, N00B_DW_AT_name, "field_a");
    n00b_dwarf_build_die_add_child(struc, m1);

    n00b_dwarf_build_die_t *m2 = n00b_dwarf_build_die_new(N00B_DW_TAG_member);
    n00b_dwarf_build_die_add_attr_str(m2, N00B_DW_AT_name, "field_b");
    n00b_dwarf_build_die_add_child(struc, m2);

    n00b_dwarf_build_die_add_child(&cu->root, struc);

    n00b_dwarf_sections_t secs = n00b_dwarf_build(builder);

    // Parse and verify structure is found.
    n00b_result_t(n00b_dwarf_info_t *) r =
        n00b_dwarf_parse_sections(
            (const uint8_t *)secs.debug_info->data,
            n00b_buffer_len(secs.debug_info),
            (const uint8_t *)secs.debug_abbrev->data,
            n00b_buffer_len(secs.debug_abbrev),
            (const uint8_t *)secs.debug_str->data,
            n00b_buffer_len(secs.debug_str),
            nullptr, 0);

    assert(n00b_result_is_ok(r));
    n00b_dwarf_info_t *dw = n00b_result_get(r);
    assert(dw->num_cus == 1);

    // The type index should find "nested_s".
    n00b_dwarf_type_def_t *t = n00b_dwarf_type_by_name(dw, "nested_s");
    assert(t != nullptr);
    assert(t->kind == N00B_DWARF_TYPE_STRUCT);
    assert(t->byte_size == 16);
    assert(t->num_members == 2);

    printf("  [PASS] build_nested_children\n");
}

// ============================================================================
// Phase 10g tests: line program builder
// ============================================================================

static void
test_line_build_simple(void)
{
    n00b_dwarf_builder_t *builder = n00b_dwarf_builder_new();
    n00b_dwarf_builder_add_cu(builder, 8);

    n00b_dwarf_build_line_t *prog = n00b_dwarf_builder_add_line_program(builder);
    assert(prog != nullptr);

    n00b_dwarf_build_line_add_dir(prog, "/src");
    uint32_t findex = n00b_dwarf_build_line_add_file(prog, "main.c", 0);
    assert(findex == 1);

    n00b_dwarf_build_line_add_row(prog, 0x1000, 1, 10, 0, true);
    n00b_dwarf_build_line_add_row(prog, 0x1008, 1, 11, 0, true);
    n00b_dwarf_build_line_add_row(prog, 0x1010, 1, 12, 0, true);
    n00b_dwarf_build_line_end_sequence(prog, 0x1020);

    n00b_dwarf_sections_t secs = n00b_dwarf_build(builder);
    assert(secs.debug_line != nullptr);
    assert(n00b_buffer_len(secs.debug_line) > 0);

    printf("  [PASS] line_build_simple\n");
}

static void
test_line_build_multi_file(void)
{
    n00b_dwarf_builder_t *builder = n00b_dwarf_builder_new();
    n00b_dwarf_builder_add_cu(builder, 8);

    n00b_dwarf_build_line_t *prog = n00b_dwarf_builder_add_line_program(builder);
    n00b_dwarf_build_line_add_dir(prog, "/src");
    uint32_t f1 = n00b_dwarf_build_line_add_file(prog, "a.c", 0);
    uint32_t f2 = n00b_dwarf_build_line_add_file(prog, "b.c", 0);
    assert(f1 == 1);
    assert(f2 == 2);

    n00b_dwarf_build_line_add_row(prog, 0x2000, f1, 1, 0, true);
    n00b_dwarf_build_line_add_row(prog, 0x2010, f2, 5, 0, true);
    n00b_dwarf_build_line_end_sequence(prog, 0x2020);

    n00b_dwarf_sections_t secs = n00b_dwarf_build(builder);
    assert(secs.debug_line != nullptr);
    assert(n00b_buffer_len(secs.debug_line) > 0);

    printf("  [PASS] line_build_multi_file\n");
}

// ============================================================================
// Phase 10d extra: codegen full header
// ============================================================================

static void
test_codegen_full_header(void)
{
    // Build a n00b_dwarf_info_t with mixed types and generate a full header.
    n00b_dwarf_info_t info = {0};

    n00b_dwarf_member_t members[1];
    members[0].name      = n00b_string_from_cstr("val");
    members[0].type_name = n00b_string_from_cstr("int");
    members[0].offset    = 0;
    members[0].size      = 4;
    members[0].bit_size  = 0;

    n00b_dwarf_enumerator_t enums[2];
    enums[0].name  = n00b_string_from_cstr("A");
    enums[0].value = 0;
    enums[1].name  = n00b_string_from_cstr("B");
    enums[1].value = 1;

    n00b_dwarf_type_def_t types[3];
    memset(types, 0, sizeof(types));

    types[0].kind        = N00B_DWARF_TYPE_STRUCT;
    types[0].name        = n00b_string_from_cstr("wrap");
    types[0].byte_size   = 4;
    types[0].members     = members;
    types[0].num_members = 1;

    types[1].kind            = N00B_DWARF_TYPE_ENUM;
    types[1].name            = n00b_string_from_cstr("mode");
    types[1].enumerators     = enums;
    types[1].num_enumerators = 2;

    types[2].kind         = N00B_DWARF_TYPE_TYPEDEF;
    types[2].name         = n00b_string_from_cstr("wrap_t");
    types[2].aliased_type = n00b_string_from_cstr("struct wrap");

    info.types     = types;
    info.num_types = 3;
    info.type_index_built = true;

    n00b_string_t *hdr = n00b_dwarf_generate_header(&info);
    assert(hdr != nullptr);
    assert(strstr(hdr->data, "#pragma once") != nullptr);
    assert(strstr(hdr->data, "#include <stdint.h>") != nullptr);
    assert(strstr(hdr->data, "struct wrap;") != nullptr);
    assert(strstr(hdr->data, "struct wrap {") != nullptr);
    assert(strstr(hdr->data, "enum mode {") != nullptr);
    assert(strstr(hdr->data, "A = 0") != nullptr);
    assert(strstr(hdr->data, "typedef struct wrap wrap_t;") != nullptr);

    printf("  [PASS] codegen_full_header\n");
}

// ============================================================================
// Phase 10e tests: line number table reader
// ============================================================================

/// Build a synthetic DWARF 4 .debug_line section for testing.
/// Contains one line program with one file, 3 rows + end_sequence.
static void
make_synthetic_debug_line(uint8_t **out_line, size_t *out_line_size)
{
    uint8_t buf[512];
    size_t  pos = 0;

    // --- Unit header ---
    size_t unit_len_pos = pos;
    put32(buf + pos, 0);  // unit_length placeholder
    pos += 4;
    put16(buf + pos, 4);  // version = 4
    pos += 2;

    size_t header_len_pos = pos;
    put32(buf + pos, 0);  // header_length placeholder
    pos += 4;

    size_t header_start = pos;

    buf[pos++] = 1;    // minimum_instruction_length
    buf[pos++] = 1;    // maximum_operations_per_instruction (v4)
    buf[pos++] = 1;    // default_is_stmt
    buf[pos++] = (uint8_t)(int8_t)-5;  // line_base = -5
    buf[pos++] = 14;   // line_range
    buf[pos++] = 13;   // opcode_base

    // standard_opcode_lengths (opcodes 1-12)
    uint8_t std_lens[] = {0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1};
    memcpy(buf + pos, std_lens, 12);
    pos += 12;

    // Directories: one dir "/test", then NUL terminator
    memcpy(buf + pos, "/test\0", 6);
    pos += 6;
    buf[pos++] = 0;  // end of directory list

    // Files: "hello.c", dir_index=1, mtime=0, size=0
    memcpy(buf + pos, "hello.c\0", 8);
    pos += 8;
    pos += encode_uleb128(buf + pos, 1);  // dir_index
    pos += encode_uleb128(buf + pos, 0);  // mtime
    pos += encode_uleb128(buf + pos, 0);  // size
    buf[pos++] = 0;  // end of file list

    // Patch header_length
    put32(buf + header_len_pos, (uint32_t)(pos - header_start));

    // --- Line program opcodes ---

    // N00B_DW_LNE_set_address(0x4000)
    buf[pos++] = 0;  // extended opcode marker
    pos += encode_uleb128(buf + pos, 9);  // length = 1 + 8
    buf[pos++] = N00B_DW_LNE_set_address;
    put64(buf + pos, 0x4000);
    pos += 8;

    // Special opcode: line 10, address 0x4000
    // adjusted_line = 10 - 1 - line_base = 10 - 1 - (-5) = 14
    // Wait: initial line=1, we want line=10 → delta=9
    // Use N00B_DW_LNS_advance_line + N00B_DW_LNS_copy instead for clarity.
    buf[pos++] = N00B_DW_LNS_advance_line;
    pos += encode_sleb128(buf + pos, 9);  // line = 1 + 9 = 10
    buf[pos++] = N00B_DW_LNS_copy;  // emit row: addr=0x4000, line=10

    // Special opcode for next row: line 11, addr 0x4004
    // line_delta = 1, addr_delta = 4
    // adjusted = (1 - (-5)) = 6; special = 6 + (4 * 14) + 13 = 75
    buf[pos++] = 75;

    // Special opcode for next row: line 12, addr 0x4008
    // line_delta = 1, addr_delta = 4
    // same: special = 75
    buf[pos++] = 75;

    // N00B_DW_LNE_end_sequence
    buf[pos++] = 0;  // extended opcode marker
    pos += encode_uleb128(buf + pos, 1);  // length = 1
    buf[pos++] = N00B_DW_LNE_end_sequence;

    // Patch unit_length
    put32(buf + unit_len_pos, (uint32_t)(pos - unit_len_pos - 4));

    uint8_t *result = n00b_alloc_array(uint8_t, pos);
    memcpy(result, buf, pos);
    *out_line      = result;
    *out_line_size = pos;
}

static void
test_line_parse_synthetic(void)
{
    // Build a minimal DWARF info with a synthetic line table.
    uint8_t *line_data;
    size_t   line_size;
    make_synthetic_debug_line(&line_data, &line_size);

    // We need a minimal debug_info + abbrev for parse_sections.
    // Use empty sections — line table parsing is independent.
    uint8_t empty_abbrev[] = {0};  // just terminator
    n00b_result_t(n00b_dwarf_info_t *) r =
        n00b_dwarf_parse_sections(nullptr, 0,
                                  empty_abbrev, 1,
                                  nullptr, 0,
                                  nullptr, 0);
    assert(n00b_result_is_ok(r));
    n00b_dwarf_info_t *dw = n00b_result_get(r);

    // Attach the line section manually.
    dw->debug_line      = line_data;
    dw->debug_line_size = line_size;

    n00b_result_t(bool) lr = n00b_dwarf_parse_line_table(dw);
    assert(n00b_result_is_ok(lr));
    assert(dw->num_line_entries >= 4);  // 3 rows + end_sequence

    // Check first row: addr=0x4000, line=10
    assert(dw->line_entries[0].address == 0x4000);
    assert(dw->line_entries[0].line == 10);
    assert(dw->line_entries[0].is_stmt == true);
    assert(dw->line_entries[0].end_sequence == false);

    // Check second row: addr=0x4004, line=11
    assert(dw->line_entries[1].address == 0x4004);
    assert(dw->line_entries[1].line == 11);

    // Check third row: addr=0x4008, line=12
    assert(dw->line_entries[2].address == 0x4008);
    assert(dw->line_entries[2].line == 12);

    // Check end_sequence
    assert(dw->line_entries[3].end_sequence == true);

    // Verify file name was resolved.
    assert(dw->line_entries[0].file != nullptr);
    assert(strcmp(dw->line_entries[0].file, "hello.c") == 0);

    printf("  [PASS] line_parse_synthetic\n");
}

static void
test_line_at_addr(void)
{
    uint8_t *line_data;
    size_t   line_size;
    make_synthetic_debug_line(&line_data, &line_size);

    uint8_t empty_abbrev[] = {0};
    n00b_result_t(n00b_dwarf_info_t *) r =
        n00b_dwarf_parse_sections(nullptr, 0,
                                  empty_abbrev, 1,
                                  nullptr, 0,
                                  nullptr, 0);
    assert(n00b_result_is_ok(r));
    n00b_dwarf_info_t *dw = n00b_result_get(r);
    dw->debug_line      = line_data;
    dw->debug_line_size = line_size;

    n00b_result_t(bool) lr = n00b_dwarf_parse_line_table(dw);
    assert(n00b_result_is_ok(lr));

    // Exact match at 0x4000 → line 10
    n00b_dwarf_line_entry_t *e = n00b_dwarf_line_at_addr(dw, 0x4000);
    assert(e != nullptr);
    assert(e->line == 10);

    // Within range at 0x4005 → line 11 (between 0x4004 and 0x4008)
    e = n00b_dwarf_line_at_addr(dw, 0x4005);
    assert(e != nullptr);
    assert(e->line == 11);

    // Before range → not found
    e = n00b_dwarf_line_at_addr(dw, 0x3000);
    assert(e == nullptr);

    printf("  [PASS] line_at_addr\n");
}

static void
test_line_build_roundtrip(void)
{
    // Build a line program, serialize, then parse and verify.
    n00b_dwarf_builder_t *builder = n00b_dwarf_builder_new();
    n00b_dwarf_builder_add_cu(builder, 8);

    n00b_dwarf_build_line_t *prog = n00b_dwarf_builder_add_line_program(builder);
    n00b_dwarf_build_line_add_dir(prog, "/home");
    uint32_t fi = n00b_dwarf_build_line_add_file(prog, "rt.c", 0);

    n00b_dwarf_build_line_add_row(prog, 0x8000, fi, 1, 0, true);
    n00b_dwarf_build_line_add_row(prog, 0x8010, fi, 5, 3, true);
    n00b_dwarf_build_line_add_row(prog, 0x8020, fi, 10, 0, true);
    n00b_dwarf_build_line_end_sequence(prog, 0x8030);

    n00b_dwarf_sections_t secs = n00b_dwarf_build(builder);
    assert(secs.debug_line != nullptr);

    // Parse the generated line table.
    uint8_t empty_abbrev[] = {0};
    n00b_result_t(n00b_dwarf_info_t *) r =
        n00b_dwarf_parse_sections(nullptr, 0,
                                  empty_abbrev, 1,
                                  nullptr, 0,
                                  nullptr, 0);
    assert(n00b_result_is_ok(r));
    n00b_dwarf_info_t *dw = n00b_result_get(r);
    dw->debug_line      = (const uint8_t *)secs.debug_line->data;
    dw->debug_line_size = n00b_buffer_len(secs.debug_line);

    n00b_result_t(bool) lr = n00b_dwarf_parse_line_table(dw);
    assert(n00b_result_is_ok(lr));
    assert(dw->num_line_entries >= 4);

    // Verify addresses and lines.
    assert(dw->line_entries[0].address == 0x8000);
    assert(dw->line_entries[0].line == 1);
    assert(dw->line_entries[1].address == 0x8010);
    assert(dw->line_entries[1].line == 5);
    assert(dw->line_entries[1].column == 3);
    assert(dw->line_entries[2].address == 0x8020);
    assert(dw->line_entries[2].line == 10);

    // End sequence
    assert(dw->line_entries[3].end_sequence == true);

    // File name
    assert(strcmp(dw->line_entries[0].file, "rt.c") == 0);

    printf("  [PASS] line_build_roundtrip\n");
}

static void
test_line_build_end_sequence(void)
{
    // Multiple sequences in one program.
    n00b_dwarf_builder_t *builder = n00b_dwarf_builder_new();
    n00b_dwarf_builder_add_cu(builder, 8);

    n00b_dwarf_build_line_t *prog = n00b_dwarf_builder_add_line_program(builder);
    n00b_dwarf_build_line_add_dir(prog, "/src");
    uint32_t fi = n00b_dwarf_build_line_add_file(prog, "seq.c", 0);

    // Sequence 1
    n00b_dwarf_build_line_add_row(prog, 0xA000, fi, 1, 0, true);
    n00b_dwarf_build_line_end_sequence(prog, 0xA010);

    // Sequence 2
    n00b_dwarf_build_line_add_row(prog, 0xB000, fi, 20, 0, true);
    n00b_dwarf_build_line_end_sequence(prog, 0xB010);

    n00b_dwarf_sections_t secs = n00b_dwarf_build(builder);
    assert(secs.debug_line != nullptr);

    uint8_t empty_abbrev[] = {0};
    n00b_result_t(n00b_dwarf_info_t *) r =
        n00b_dwarf_parse_sections(nullptr, 0,
                                  empty_abbrev, 1,
                                  nullptr, 0,
                                  nullptr, 0);
    assert(n00b_result_is_ok(r));
    n00b_dwarf_info_t *dw = n00b_result_get(r);
    dw->debug_line      = (const uint8_t *)secs.debug_line->data;
    dw->debug_line_size = n00b_buffer_len(secs.debug_line);

    n00b_result_t(bool) lr = n00b_dwarf_parse_line_table(dw);
    assert(n00b_result_is_ok(lr));

    // Should have at least 4 entries (2 rows + 2 end_sequences)
    assert(dw->num_line_entries >= 4);

    // Find both end_sequence markers.
    int end_count = 0;
    for (size_t i = 0; i < dw->num_line_entries; i++) {
        if (dw->line_entries[i].end_sequence) {
            end_count++;
        }
    }
    assert(end_count == 2);

    printf("  [PASS] line_build_end_sequence\n");
}

// ============================================================================
// Phase 10f extra: builder struct type + string dedup
// ============================================================================

static void
test_build_struct_type(void)
{
    n00b_dwarf_builder_t *builder = n00b_dwarf_builder_new();
    n00b_dwarf_build_cu_t *cu = n00b_dwarf_builder_add_cu(builder, 8);

    // Build a struct with base_type and typedef.
    n00b_dwarf_build_die_t *base = n00b_dwarf_build_die_new(N00B_DW_TAG_base_type);
    n00b_dwarf_build_die_add_attr_str(base, N00B_DW_AT_name, "int");
    n00b_dwarf_build_die_add_attr_u64(base, N00B_DW_AT_byte_size, N00B_DW_FORM_data1, 4);
    n00b_dwarf_build_die_add_attr_u64(base, N00B_DW_AT_encoding, N00B_DW_FORM_data1, N00B_DW_ATE_signed);
    n00b_dwarf_build_die_add_child(&cu->root, base);

    n00b_dwarf_build_die_t *td = n00b_dwarf_build_die_new(N00B_DW_TAG_typedef);
    n00b_dwarf_build_die_add_attr_str(td, N00B_DW_AT_name, "myint");
    n00b_dwarf_build_die_add_child(&cu->root, td);

    n00b_dwarf_sections_t secs = n00b_dwarf_build(builder);

    // Parse and verify the types are found.
    n00b_result_t(n00b_dwarf_info_t *) r =
        n00b_dwarf_parse_sections(
            (const uint8_t *)secs.debug_info->data,
            n00b_buffer_len(secs.debug_info),
            (const uint8_t *)secs.debug_abbrev->data,
            n00b_buffer_len(secs.debug_abbrev),
            (const uint8_t *)secs.debug_str->data,
            n00b_buffer_len(secs.debug_str),
            nullptr, 0);
    assert(n00b_result_is_ok(r));
    n00b_dwarf_info_t *dw = n00b_result_get(r);

    n00b_dwarf_type_def_t *t = n00b_dwarf_type_by_name(dw, "myint");
    assert(t != nullptr);
    assert(t->kind == N00B_DWARF_TYPE_TYPEDEF);

    printf("  [PASS] build_struct_type\n");
}

static void
test_build_string_dedup(void)
{
    // Use the same string in multiple attributes — verify the string table
    // doesn't grow linearly (deduplication).
    n00b_dwarf_builder_t *builder = n00b_dwarf_builder_new();
    n00b_dwarf_build_cu_t *cu = n00b_dwarf_builder_add_cu(builder, 8);

    n00b_dwarf_build_die_add_attr_str(&cu->root, N00B_DW_AT_name, "repeated");
    n00b_dwarf_build_die_add_attr_str(&cu->root, N00B_DW_AT_comp_dir, "repeated");

    n00b_dwarf_build_die_t *sub = n00b_dwarf_build_die_new(N00B_DW_TAG_subprogram);
    n00b_dwarf_build_die_add_attr_str(sub, N00B_DW_AT_name, "repeated");
    n00b_dwarf_build_die_add_attr_str(sub, N00B_DW_AT_linkage_name, "unique_name");
    n00b_dwarf_build_die_add_child(&cu->root, sub);

    n00b_dwarf_sections_t secs = n00b_dwarf_build(builder);

    // The string table should contain "repeated" only once + "unique_name" once.
    // Minimum: "" + "repeated" + "unique_name" = 1 + 9 + 12 = 22 bytes.
    // Without dedup it would be 1 + 9*3 + 12 = 40 bytes.
    size_t str_len = n00b_buffer_len(secs.debug_str);
    assert(str_len < 35);  // Must be deduplicated (well under 40).
    assert(str_len >= 22);

    printf("  [PASS] build_string_dedup\n");
}

// ============================================================================
// Phase 10h tests: integration
// ============================================================================

static void
test_abstract_dwarf_dispatch(void)
{
    // Test that n00b_binary_dwarf returns an error for unsupported formats.
    // We can test the nullptr and unknown-format paths.
    n00b_result_t(n00b_dwarf_info_t *) r = n00b_binary_dwarf(nullptr);
    assert(n00b_result_is_err(r));

    // Create a binary with PE format — should return N00B_ERR_NOT_SUPPORTED.
    n00b_binary_t fake_pe = {0};
    fake_pe.format = N00B_FMT_PE;
    r = n00b_binary_dwarf(&fake_pe);
    assert(n00b_result_is_err(r));

    printf("  [PASS] abstract_dwarf_dispatch\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running DWARF tests...\n");

    // Phase 10a: constants + types
    test_dwarf_constants();
    test_dwarf_attr_size();
    test_dwarf_cu_header_size();

    // Phase 10b: core reader
    test_parse_abbrev_table();
    test_parse_cu_header_v4();
    test_parse_cu_header_v5();
    test_parse_die_simple();
    test_parse_attr_forms();
    test_skip_die();
    test_multi_cu();
    test_empty_debug_info();

    // Phase 10c: function + type indexing + query
    test_func_index_build();
    test_func_at_addr();
    test_func_by_name();
    test_type_struct();
    test_type_enum();
    test_type_typedef();

    // Phase 10d: code generation
    test_codegen_struct();
    test_codegen_enum();
    test_codegen_typedef();
    test_codegen_null();
    test_codegen_full_header();

    // Phase 10e: line table reader
    test_line_parse_synthetic();
    test_line_at_addr();

    // Phase 10f: DWARF builder
    test_build_empty_cu();
    test_build_simple_subprogram();
    test_build_roundtrip();
    test_build_multi_cu();
    test_build_nested_children();
    test_build_struct_type();
    test_build_string_dedup();

    // Phase 10g: line program builder
    test_line_build_simple();
    test_line_build_multi_file();
    test_line_build_roundtrip();
    test_line_build_end_sequence();

    // Phase 10h: integration
    test_abstract_dwarf_dispatch();

    printf("All DWARF tests passed.\n");
    n00b_shutdown();
    return 0;
}

/**
 * @file n00b_dwarf_build.c
 * @brief DWARF section builder / serializer.
 *
 * Builds .debug_info, .debug_abbrev, .debug_str, and .debug_line
 * sections programmatically.  Targets DWARF version 4 output.
 *
 * Also handles integration with ELF and Mach-O builders.
 */

#include <string.h>
#include <stdio.h>
#include "compiler/objfile/dwarf.h"
#include "compiler/objfile/elf.h"
#include "compiler/objfile/elf_build.h"
#include "compiler/objfile/macho.h"
#include "compiler/objfile/macho_build.h"

// ============================================================================
// Inline LEB128 encoders
// ============================================================================

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

static size_t
encode_sleb128(uint8_t *buf, int64_t value)
{
    size_t n    = 0;
    bool   more = true;
    while (more) {
        uint8_t byte = value & 0x7f;
        value >>= 7;
        if ((value == 0 && !(byte & 0x40))
            || (value == -1 && (byte & 0x40))) {
            more = false;
        } else {
            byte |= 0x80;
        }
        buf[n++] = byte;
    }
    return n;
}

static void
writer_write_uleb128(n00b_writer_t *w, uint64_t value)
{
    uint8_t buf[10];
    size_t  n = encode_uleb128(buf, value);
    n00b_writer_write_bytes(w, buf, n);
}

static void
writer_write_sleb128(n00b_writer_t *w, int64_t value)
{
    uint8_t buf[10];
    size_t  n = encode_sleb128(buf, value);
    n00b_writer_write_bytes(w, buf, n);
}

// Forward declaration.
static n00b_buffer_t *build_line_section(n00b_dwarf_build_line_t *prog);

// ============================================================================
// Builder creation
// ============================================================================

n00b_dwarf_builder_t *
n00b_dwarf_builder_new(void)
{
    n00b_dwarf_builder_t *b = n00b_alloc(n00b_dwarf_builder_t);
    memset(b, 0, sizeof(*b));
    b->cus_cap = 4;
    b->cus     = n00b_alloc_array(n00b_dwarf_build_cu_t, b->cus_cap);
    return b;
}

n00b_dwarf_build_cu_t *
n00b_dwarf_builder_add_cu(n00b_dwarf_builder_t *builder, uint8_t address_size)
{
    if (builder->num_cus >= builder->cus_cap) {
        builder->cus_cap *= 2;
        n00b_dwarf_build_cu_t *nc =
            n00b_alloc_array(n00b_dwarf_build_cu_t, builder->cus_cap);
        memcpy(nc, builder->cus,
               builder->num_cus * sizeof(n00b_dwarf_build_cu_t));
        builder->cus = nc;
    }

    n00b_dwarf_build_cu_t *cu = &builder->cus[builder->num_cus++];
    memset(cu, 0, sizeof(*cu));
    cu->address_size = address_size;
    cu->root.tag = N00B_DW_TAG_compile_unit;
    cu->root.attr_cap = 8;
    cu->root.attrs = n00b_alloc_array(n00b_dwarf_build_attr_t, cu->root.attr_cap);
    cu->root.children_cap = 8;
    cu->root.children = n00b_alloc_array(n00b_dwarf_build_die_t, cu->root.children_cap);
    return cu;
}

// ============================================================================
// DIE builder
// ============================================================================

n00b_dwarf_build_die_t *
n00b_dwarf_build_die_new(uint64_t tag)
{
    n00b_dwarf_build_die_t *die = n00b_alloc(n00b_dwarf_build_die_t);
    memset(die, 0, sizeof(*die));
    die->tag = tag;
    die->attr_cap = 8;
    die->attrs = n00b_alloc_array(n00b_dwarf_build_attr_t, die->attr_cap);
    die->children_cap = 4;
    die->children = n00b_alloc_array(n00b_dwarf_build_die_t, die->children_cap);
    return die;
}

static void
die_add_attr(n00b_dwarf_build_die_t *die, n00b_dwarf_build_attr_t attr)
{
    if (die->attr_count >= die->attr_cap) {
        die->attr_cap *= 2;
        n00b_dwarf_build_attr_t *na =
            n00b_alloc_array(n00b_dwarf_build_attr_t, die->attr_cap);
        memcpy(na, die->attrs,
               die->attr_count * sizeof(n00b_dwarf_build_attr_t));
        die->attrs = na;
    }
    die->attrs[die->attr_count++] = attr;
}

void
n00b_dwarf_build_die_add_attr_str(n00b_dwarf_build_die_t *die,
                                   uint64_t name, const char *str)
{
    n00b_dwarf_build_attr_t a = {0};
    a.name = name;
    a.form = N00B_DW_FORM_strp;
    a.str  = str;
    die_add_attr(die, a);
}

void
n00b_dwarf_build_die_add_attr_u64(n00b_dwarf_build_die_t *die,
                                   uint64_t name, uint64_t form,
                                   uint64_t value)
{
    n00b_dwarf_build_attr_t a = {0};
    a.name = name;
    a.form = form;
    a.u64  = value;
    die_add_attr(die, a);
}

void
n00b_dwarf_build_die_add_attr_addr(n00b_dwarf_build_die_t *die,
                                    uint64_t name, uint64_t addr)
{
    n00b_dwarf_build_attr_t a = {0};
    a.name = name;
    a.form = N00B_DW_FORM_addr;
    a.u64  = addr;
    die_add_attr(die, a);
}

void
n00b_dwarf_build_die_add_child(n00b_dwarf_build_die_t *parent,
                                n00b_dwarf_build_die_t *child)
{
    if (parent->num_children >= parent->children_cap) {
        parent->children_cap *= 2;
        n00b_dwarf_build_die_t *nc =
            n00b_alloc_array(n00b_dwarf_build_die_t, parent->children_cap);
        memcpy(nc, parent->children,
               parent->num_children * sizeof(n00b_dwarf_build_die_t));
        parent->children = nc;
    }
    parent->children[parent->num_children++] = *child;
}

// ============================================================================
// Abbreviation generation
// ============================================================================

/// An abbreviation "signature" for deduplication.
typedef struct {
    uint64_t tag;
    bool     has_children;
    uint64_t *attr_names;
    uint64_t *attr_forms;
    size_t   attr_count;
    uint64_t code;  // Assigned abbreviation code (1-based).
} abbrev_sig_t;

typedef struct {
    abbrev_sig_t *sigs;
    size_t        count;
    size_t        cap;
} abbrev_set_t;

static void
abbrev_set_init(abbrev_set_t *set)
{
    set->count = 0;
    set->cap   = 16;
    set->sigs  = n00b_alloc_array(abbrev_sig_t, set->cap);
}

/// Find or add an abbreviation signature.  Returns the abbreviation code.
static uint64_t
abbrev_set_add(abbrev_set_t *set, const n00b_dwarf_build_die_t *die)
{
    bool has_children = (die->num_children > 0);

    // Check for existing match.
    for (size_t i = 0; i < set->count; i++) {
        abbrev_sig_t *s = &set->sigs[i];
        if (s->tag != die->tag || s->has_children != has_children
            || s->attr_count != die->attr_count) {
            continue;
        }
        bool match = true;
        for (size_t j = 0; j < die->attr_count; j++) {
            if (s->attr_names[j] != die->attrs[j].name
                || s->attr_forms[j] != die->attrs[j].form) {
                match = false;
                break;
            }
        }
        if (match) {
            return s->code;
        }
    }

    // Add new entry.
    if (set->count >= set->cap) {
        set->cap *= 2;
        abbrev_sig_t *ns = n00b_alloc_array(abbrev_sig_t, set->cap);
        memcpy(ns, set->sigs, set->count * sizeof(abbrev_sig_t));
        set->sigs = ns;
    }

    uint64_t code = set->count + 1;
    abbrev_sig_t *s = &set->sigs[set->count++];
    s->tag          = die->tag;
    s->has_children = has_children;
    s->attr_count   = die->attr_count;
    s->code         = code;

    if (die->attr_count > 0) {
        s->attr_names = n00b_alloc_array(uint64_t, die->attr_count);
        s->attr_forms = n00b_alloc_array(uint64_t, die->attr_count);
        for (size_t j = 0; j < die->attr_count; j++) {
            s->attr_names[j] = die->attrs[j].name;
            s->attr_forms[j] = die->attrs[j].form;
        }
    }

    return code;
}

/// Recursively register abbreviations for a DIE tree.
static void
collect_abbrevs(abbrev_set_t *set, n00b_dwarf_build_die_t *die)
{
    abbrev_set_add(set, die);
    for (size_t i = 0; i < die->num_children; i++) {
        collect_abbrevs(set, &die->children[i]);
    }
}

/// Write the .debug_abbrev section.
static void
write_abbrev_section(abbrev_set_t *set, n00b_writer_t *w)
{
    for (size_t i = 0; i < set->count; i++) {
        abbrev_sig_t *s = &set->sigs[i];
        writer_write_uleb128(w, s->code);
        writer_write_uleb128(w, s->tag);
        n00b_writer_write_u8(w, s->has_children ? N00B_DW_CHILDREN_yes
                                                 : N00B_DW_CHILDREN_no);
        for (size_t j = 0; j < s->attr_count; j++) {
            writer_write_uleb128(w, s->attr_names[j]);
            writer_write_uleb128(w, s->attr_forms[j]);
        }
        // End of attr specs.
        writer_write_uleb128(w, 0);
        writer_write_uleb128(w, 0);
    }
    // Terminating 0 code.
    n00b_writer_write_u8(w, 0);
}

// ============================================================================
// String table
// ============================================================================

typedef struct {
    char   *data;
    size_t  len;
    size_t  cap;
} str_table_t;

static void
str_table_init(str_table_t *st)
{
    st->cap  = 256;
    st->len  = 1;  // First byte is NUL (empty string at offset 0).
    st->data = n00b_alloc_array(char, st->cap);
    st->data[0] = '\0';
}

/// Add a string, returning its offset.  Deduplicates.
static uint32_t
str_table_add(str_table_t *st, const char *s)
{
    if (!s || s[0] == '\0') {
        return 0;
    }

    size_t slen = strlen(s);

    // Linear scan for deduplication.
    for (size_t off = 1; off < st->len;) {
        if (strcmp(st->data + off, s) == 0) {
            return (uint32_t)off;
        }
        off += strlen(st->data + off) + 1;
    }

    // Append.
    while (st->len + slen + 1 > st->cap) {
        st->cap *= 2;
        char *nd = n00b_alloc_array(char, st->cap);
        memcpy(nd, st->data, st->len);
        st->data = nd;
    }

    uint32_t offset = (uint32_t)st->len;
    memcpy(st->data + st->len, s, slen + 1);
    st->len += slen + 1;
    return offset;
}

// ============================================================================
// DIE serializer
// ============================================================================

static void
write_die(n00b_dwarf_build_die_t *die, uint8_t address_size,
          abbrev_set_t *abbrevs, str_table_t *strtab,
          n00b_writer_t *w)
{
    uint64_t code = abbrev_set_add(abbrevs, die);
    writer_write_uleb128(w, code);

    // Write attribute values.
    for (size_t i = 0; i < die->attr_count; i++) {
        n00b_dwarf_build_attr_t *a = &die->attrs[i];
        switch (a->form) {
        case N00B_DW_FORM_strp: {
            uint32_t offset = str_table_add(strtab, a->str);
            n00b_writer_write_u32(w, offset);
            break;
        }
        case N00B_DW_FORM_addr:
            if (address_size == 8) {
                n00b_writer_write_u64(w, a->u64);
            } else {
                n00b_writer_write_u32(w, (uint32_t)a->u64);
            }
            break;
        case N00B_DW_FORM_data1:
            n00b_writer_write_u8(w, (uint8_t)a->u64);
            break;
        case N00B_DW_FORM_data2:
            n00b_writer_write_u16(w, (uint16_t)a->u64);
            break;
        case N00B_DW_FORM_data4:
            n00b_writer_write_u32(w, (uint32_t)a->u64);
            break;
        case N00B_DW_FORM_data8:
            n00b_writer_write_u64(w, a->u64);
            break;
        case N00B_DW_FORM_udata:
            writer_write_uleb128(w, a->u64);
            break;
        case N00B_DW_FORM_sdata:
            writer_write_sleb128(w, a->s64);
            break;
        case N00B_DW_FORM_flag_present:
            // No data to write.
            break;
        case N00B_DW_FORM_string:
            if (a->str) {
                n00b_writer_write_bytes(w, (const uint8_t *)a->str,
                                        strlen(a->str) + 1);
            } else {
                n00b_writer_write_u8(w, 0);
            }
            break;
        case N00B_DW_FORM_sec_offset:
            n00b_writer_write_u32(w, (uint32_t)a->u64);
            break;
        default:
            // Fall back to data4.
            n00b_writer_write_u32(w, (uint32_t)a->u64);
            break;
        }
    }

    // Write children.
    for (size_t i = 0; i < die->num_children; i++) {
        write_die(&die->children[i], address_size, abbrevs, strtab, w);
    }

    // Null terminator if has children.
    if (die->num_children > 0) {
        n00b_writer_write_u8(w, 0);
    }
}

// ============================================================================
// Top-level build
// ============================================================================

n00b_dwarf_sections_t
n00b_dwarf_build(n00b_dwarf_builder_t *builder)
{
    n00b_dwarf_sections_t result = {0};

    if (!builder || builder->num_cus == 0) {
        result.debug_info   = n00b_buffer_new(0);
        result.debug_abbrev = n00b_buffer_new(0);
        result.debug_str    = n00b_buffer_new(0);
        return result;
    }

    // Collect all abbreviations.
    abbrev_set_t abbrevs;
    abbrev_set_init(&abbrevs);
    for (size_t i = 0; i < builder->num_cus; i++) {
        collect_abbrevs(&abbrevs, &builder->cus[i].root);
    }

    // Build string table.
    str_table_t strtab;
    str_table_init(&strtab);

    // Write .debug_abbrev.
    n00b_writer_t *aw = n00b_writer_new(256);
    write_abbrev_section(&abbrevs, aw);
    result.debug_abbrev = n00b_writer_finalize(aw);

    // Write .debug_info.
    n00b_writer_t *iw = n00b_writer_new(512);

    for (size_t ci = 0; ci < builder->num_cus; ci++) {
        n00b_dwarf_build_cu_t *cu = &builder->cus[ci];
        uint8_t addr_sz = cu->address_size ? cu->address_size : 8;

        // CU header (DWARF 4, 32-bit format).
        size_t length_pos = n00b_writer_pos(iw);
        n00b_writer_write_u32(iw, 0);  // unit_length placeholder
        n00b_writer_write_u16(iw, 4);  // version
        n00b_writer_write_u32(iw, 0);  // abbrev_offset (always 0 — single table)
        n00b_writer_write_u8(iw, addr_sz);

        // Write root DIE + children.
        write_die(&cu->root, addr_sz, &abbrevs, &strtab, iw);

        // Patch unit_length.
        size_t end_pos    = n00b_writer_pos(iw);
        uint32_t unit_len = (uint32_t)(end_pos - length_pos - 4);
        n00b_writer_patch_u32(iw, length_pos, unit_len);
    }

    result.debug_info = n00b_writer_finalize(iw);

    // Write .debug_str.
    n00b_writer_t *sw = n00b_writer_new(strtab.len);
    n00b_writer_write_bytes(sw, (const uint8_t *)strtab.data, strtab.len);
    result.debug_str = n00b_writer_finalize(sw);

    // Line table.
    if (builder->line_program) {
        result.debug_line = build_line_section(builder->line_program);
    }

    return result;
}

// ============================================================================
// Line program builder (Phase 10g)
// ============================================================================

n00b_dwarf_build_line_t *
n00b_dwarf_builder_add_line_program(n00b_dwarf_builder_t *builder)
{
    n00b_dwarf_build_line_t *prog = n00b_alloc(n00b_dwarf_build_line_t);
    memset(prog, 0, sizeof(*prog));
    prog->min_insn_length = 1;
    prog->line_base       = -5;
    prog->line_range      = 14;
    prog->dirs_cap  = 8;
    prog->dirs      = n00b_alloc_array(n00b_dwarf_build_dir_t, prog->dirs_cap);
    prog->files_cap = 8;
    prog->files     = n00b_alloc_array(n00b_dwarf_build_file_t, prog->files_cap);
    prog->rows_cap  = 64;
    prog->rows      = n00b_alloc_array(n00b_dwarf_build_line_row_t, prog->rows_cap);
    builder->line_program = prog;
    return prog;
}

void
n00b_dwarf_build_line_add_dir(n00b_dwarf_build_line_t *prog, const char *dir)
{
    if (prog->num_dirs >= prog->dirs_cap) {
        prog->dirs_cap *= 2;
        n00b_dwarf_build_dir_t *nd =
            n00b_alloc_array(n00b_dwarf_build_dir_t, prog->dirs_cap);
        memcpy(nd, prog->dirs,
               prog->num_dirs * sizeof(n00b_dwarf_build_dir_t));
        prog->dirs = nd;
    }
    prog->dirs[prog->num_dirs].directory = n00b_string_from_cstr(dir);
    prog->num_dirs++;
}

uint32_t
n00b_dwarf_build_line_add_file(n00b_dwarf_build_line_t *prog,
                                const char *name, uint32_t dir_index)
{
    if (prog->num_files >= prog->files_cap) {
        prog->files_cap *= 2;
        n00b_dwarf_build_file_t *nf =
            n00b_alloc_array(n00b_dwarf_build_file_t, prog->files_cap);
        memcpy(nf, prog->files,
               prog->num_files * sizeof(n00b_dwarf_build_file_t));
        prog->files = nf;
    }
    uint32_t idx = (uint32_t)(prog->num_files + 1);  // 1-based
    prog->files[prog->num_files].name = n00b_string_from_cstr(name);
    prog->files[prog->num_files].dir_index = dir_index;
    prog->num_files++;
    return idx;
}

void
n00b_dwarf_build_line_add_row(n00b_dwarf_build_line_t *prog,
                               uint64_t address, uint32_t file,
                               uint32_t line, uint16_t column, bool is_stmt)
{
    if (prog->num_rows >= prog->rows_cap) {
        prog->rows_cap *= 2;
        n00b_dwarf_build_line_row_t *nr =
            n00b_alloc_array(n00b_dwarf_build_line_row_t, prog->rows_cap);
        memcpy(nr, prog->rows,
               prog->num_rows * sizeof(n00b_dwarf_build_line_row_t));
        prog->rows = nr;
    }
    n00b_dwarf_build_line_row_t *r = &prog->rows[prog->num_rows++];
    r->address      = address;
    r->file_index   = file;
    r->line         = line;
    r->column       = column;
    r->is_stmt      = is_stmt;
    r->end_sequence = false;
}

void
n00b_dwarf_build_line_end_sequence(n00b_dwarf_build_line_t *prog,
                                    uint64_t address)
{
    if (prog->num_rows >= prog->rows_cap) {
        prog->rows_cap *= 2;
        n00b_dwarf_build_line_row_t *nr =
            n00b_alloc_array(n00b_dwarf_build_line_row_t, prog->rows_cap);
        memcpy(nr, prog->rows,
               prog->num_rows * sizeof(n00b_dwarf_build_line_row_t));
        prog->rows = nr;
    }
    n00b_dwarf_build_line_row_t *r = &prog->rows[prog->num_rows++];
    r->address      = address;
    r->file_index   = 0;
    r->line         = 0;
    r->column       = 0;
    r->is_stmt      = false;
    r->end_sequence = true;
}

/// Build the .debug_line section from the line program.
static n00b_buffer_t *
build_line_section(n00b_dwarf_build_line_t *prog)
{
    n00b_writer_t *w = n00b_writer_new(512);

    uint8_t opcode_base  = 13;  // Standard opcodes 1-12.
    uint8_t line_range   = prog->line_range;
    int8_t  line_base    = prog->line_base;
    uint8_t min_insn_len = prog->min_insn_length;

    // Unit length placeholder.
    size_t length_pos = n00b_writer_pos(w);
    n00b_writer_write_u32(w, 0);

    // Version = 4.
    n00b_writer_write_u16(w, 4);

    // Header length placeholder.
    size_t header_length_pos = n00b_writer_pos(w);
    n00b_writer_write_u32(w, 0);

    size_t header_start = n00b_writer_pos(w);

    // Parameters.
    n00b_writer_write_u8(w, min_insn_len);      // minimum_instruction_length
    n00b_writer_write_u8(w, 1);                  // maximum_operations_per_instruction
    n00b_writer_write_u8(w, 1);                  // default_is_stmt
    n00b_writer_write_u8(w, (uint8_t)line_base); // line_base
    n00b_writer_write_u8(w, line_range);         // line_range
    n00b_writer_write_u8(w, opcode_base);        // opcode_base

    // Standard opcode lengths.
    static const uint8_t std_lengths[12] = {
        0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1
    };
    n00b_writer_write_bytes(w, std_lengths, 12);

    // Directory entries.
    for (size_t i = 0; i < prog->num_dirs; i++) {
        const char *d = prog->dirs[i].directory->data;
        n00b_writer_write_bytes(w, (const uint8_t *)d, strlen(d) + 1);
    }
    n00b_writer_write_u8(w, 0);  // terminator

    // File entries.
    for (size_t i = 0; i < prog->num_files; i++) {
        const char *f = prog->files[i].name->data;
        n00b_writer_write_bytes(w, (const uint8_t *)f, strlen(f) + 1);
        writer_write_uleb128(w, prog->files[i].dir_index);
        writer_write_uleb128(w, 0);  // timestamp
        writer_write_uleb128(w, 0);  // file size
    }
    n00b_writer_write_u8(w, 0);  // terminator

    // Patch header_length.
    size_t header_end = n00b_writer_pos(w);
    n00b_writer_patch_u32(w, header_length_pos,
                          (uint32_t)(header_end - header_start));

    // Encode line program opcodes.
    uint64_t cur_addr = 0;
    uint32_t cur_file = 1;
    uint32_t cur_line = 1;
    uint16_t cur_col  = 0;
    bool     cur_stmt = true;

    for (size_t i = 0; i < prog->num_rows; i++) {
        n00b_dwarf_build_line_row_t *row = &prog->rows[i];

        if (row->end_sequence) {
            // N00B_DW_LNS_advance_pc if needed.
            if (row->address > cur_addr) {
                n00b_writer_write_u8(w, N00B_DW_LNS_advance_pc);
                writer_write_uleb128(w,
                    (row->address - cur_addr) / min_insn_len);
            }
            // N00B_DW_LNE_end_sequence.
            n00b_writer_write_u8(w, 0);  // extended opcode marker
            writer_write_uleb128(w, 1);  // length = 1
            n00b_writer_write_u8(w, N00B_DW_LNE_end_sequence);

            cur_addr = 0;
            cur_file = 1;
            cur_line = 1;
            cur_col  = 0;
            cur_stmt = true;
            continue;
        }

        // Set address if first row or after end_sequence.
        if (i == 0 || (i > 0 && prog->rows[i - 1].end_sequence)) {
            // N00B_DW_LNE_set_address.
            n00b_writer_write_u8(w, 0);        // extended opcode marker
            writer_write_uleb128(w, 1 + 8);    // length = 1 + address_size
            n00b_writer_write_u8(w, N00B_DW_LNE_set_address);
            n00b_writer_write_u64(w, row->address);
            cur_addr = row->address;
        }

        // Update file.
        if (row->file_index != cur_file) {
            n00b_writer_write_u8(w, N00B_DW_LNS_set_file);
            writer_write_uleb128(w, row->file_index);
            cur_file = row->file_index;
        }

        // Update column.
        if (row->column != cur_col) {
            n00b_writer_write_u8(w, N00B_DW_LNS_set_column);
            writer_write_uleb128(w, row->column);
            cur_col = row->column;
        }

        // Update is_stmt.
        if (row->is_stmt != cur_stmt) {
            n00b_writer_write_u8(w, N00B_DW_LNS_negate_stmt);
            cur_stmt = row->is_stmt;
        }

        // Compute address and line deltas.
        int64_t  line_delta = (int64_t)row->line - (int64_t)cur_line;
        uint64_t addr_delta = (row->address - cur_addr) / min_insn_len;

        // Try special opcode.
        int64_t adjusted_line = line_delta - line_base;
        if (adjusted_line >= 0 && adjusted_line < line_range) {
            uint64_t special = adjusted_line + (addr_delta * line_range)
                             + opcode_base;
            if (special <= 255) {
                n00b_writer_write_u8(w, (uint8_t)special);
                cur_addr = row->address;
                cur_line = row->line;
                continue;
            }
        }

        // Fall back to standard opcodes.
        if (addr_delta > 0) {
            n00b_writer_write_u8(w, N00B_DW_LNS_advance_pc);
            writer_write_uleb128(w, addr_delta);
        }
        if (line_delta != 0) {
            n00b_writer_write_u8(w, N00B_DW_LNS_advance_line);
            writer_write_sleb128(w, line_delta);
        }
        n00b_writer_write_u8(w, N00B_DW_LNS_copy);

        cur_addr = row->address;
        cur_line = row->line;
    }

    // Patch unit_length.
    size_t end_pos    = n00b_writer_pos(w);
    uint32_t unit_len = (uint32_t)(end_pos - length_pos - 4);
    n00b_writer_patch_u32(w, length_pos, unit_len);

    return n00b_writer_finalize(w);
}

// ============================================================================
// ELF / Mach-O integration (Phase 10h)
// ============================================================================

void
n00b_elf_add_dwarf(n00b_elf_binary_t *bin, n00b_dwarf_sections_t sections)
{
    if (!bin) {
        return;
    }

    // SHT_PROGBITS = 1, no alloc flags (debug sections aren't loaded).
    if (sections.debug_info && n00b_buffer_len(sections.debug_info) > 0) {
        n00b_elf_section_t *s =
            n00b_elf_add_section(bin, r".debug_info", 1, 0);
        s->content = sections.debug_info;
    }
    if (sections.debug_abbrev && n00b_buffer_len(sections.debug_abbrev) > 0) {
        n00b_elf_section_t *s =
            n00b_elf_add_section(bin, r".debug_abbrev", 1, 0);
        s->content = sections.debug_abbrev;
    }
    if (sections.debug_str && n00b_buffer_len(sections.debug_str) > 0) {
        n00b_elf_section_t *s =
            n00b_elf_add_section(bin, r".debug_str", 1, 0);
        s->content = sections.debug_str;
    }
    if (sections.debug_line && n00b_buffer_len(sections.debug_line) > 0) {
        n00b_elf_section_t *s =
            n00b_elf_add_section(bin, r".debug_line", 1, 0);
        s->content = sections.debug_line;
    }
}

void
n00b_macho_add_dwarf(n00b_macho_binary_t *bin, n00b_dwarf_sections_t sections)
{
    if (!bin) {
        return;
    }

    // Find or create the __DWARF segment.
    n00b_macho_segment_t *dwarf_seg = nullptr;
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        if (strncmp(bin->segments[i].name, "__DWARF", 7) == 0) {
            dwarf_seg = &bin->segments[i];
            break;
        }
    }
    if (!dwarf_seg) {
        dwarf_seg = n00b_macho_add_segment(bin, "__DWARF", 0, 0);
    }

    if (sections.debug_info && n00b_buffer_len(sections.debug_info) > 0) {
        n00b_macho_section_t *s =
            n00b_macho_add_section(dwarf_seg, "__debug_info", "__DWARF", 0, 0);
        s->content = sections.debug_info;
    }
    if (sections.debug_abbrev && n00b_buffer_len(sections.debug_abbrev) > 0) {
        n00b_macho_section_t *s =
            n00b_macho_add_section(dwarf_seg, "__debug_abbrev", "__DWARF", 0, 0);
        s->content = sections.debug_abbrev;
    }
    if (sections.debug_str && n00b_buffer_len(sections.debug_str) > 0) {
        n00b_macho_section_t *s =
            n00b_macho_add_section(dwarf_seg, "__debug_str", "__DWARF", 0, 0);
        s->content = sections.debug_str;
    }
    if (sections.debug_line && n00b_buffer_len(sections.debug_line) > 0) {
        n00b_macho_section_t *s =
            n00b_macho_add_section(dwarf_seg, "__debug_line", "__DWARF", 0, 0);
        s->content = sections.debug_line;
    }
}

/**
 * @file n00b_dwarf_query.c
 * @brief DWARF function and type indexing + query API.
 *
 * Walks all compilation units to build searchable indices of functions
 * and types.  Provides lookup by address and name.
 *
 * Ported from slop/src/demangle/dwarf/dwarf_params.c and dwarf_types.c.
 */

#include <string.h>
#include <stdio.h>
#include "compiler/objfile/dwarf.h"

// ============================================================================
// Inline ULEB128 decoder (needed before parse_members)
// ============================================================================

static inline uint64_t
dwarf_decode_uleb128_inline(const uint8_t *p, size_t *bytes_read)
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

// ============================================================================
// Internal helpers
// ============================================================================

/// Get the abbreviation table for a CU, parsing if needed.
static n00b_dwarf_abbrev_table_t *
query_get_abbrev(n00b_dwarf_info_t *info, n00b_dwarf_cu_t *cu)
{
    // Check existing tables — simple linear search since count is small.
    // We just always parse fresh per CU since the cache may have them.
    return n00b_dwarf_parse_abbrev_table(info->debug_abbrev,
                                         info->debug_abbrev_size,
                                         cu->abbrev_offset);
}

/// Resolve a type DIE reference to a human-readable type name string.
/// Returns a static or allocated string.
static const char *
resolve_type_name(n00b_dwarf_info_t     *info,
                  n00b_dwarf_cu_t       *cu,
                  n00b_dwarf_abbrev_table_t *table,
                  uint64_t               type_offset)
{
    n00b_dwarf_die_t die = {0};
    if (!n00b_dwarf_parse_die(info, table, cu, type_offset, &die)) {
        return "?";
    }

    const n00b_dwarf_attr_t *name_attr =
        n00b_dwarf_die_get_attr(&die, N00B_DW_AT_name);

    switch (die.tag) {
    case N00B_DW_TAG_base_type:
    case N00B_DW_TAG_structure_type:
    case N00B_DW_TAG_class_type:
    case N00B_DW_TAG_union_type:
    case N00B_DW_TAG_enumeration_type:
    case N00B_DW_TAG_typedef:
        return name_attr ? name_attr->str : "?";

    case N00B_DW_TAG_pointer_type: {
        const n00b_dwarf_attr_t *tattr =
            n00b_dwarf_die_get_attr(&die, N00B_DW_AT_type);
        if (tattr) {
            const char *base = resolve_type_name(info, cu, table, tattr->u64);
            // Build "base *" string.
            size_t len = strlen(base);
            char  *buf = n00b_alloc_array(char, len + 3);
            memcpy(buf, base, len);
            buf[len]     = ' ';
            buf[len + 1] = '*';
            buf[len + 2] = '\0';
            return buf;
        }
        return "void *";
    }

    case N00B_DW_TAG_const_type: {
        const n00b_dwarf_attr_t *tattr =
            n00b_dwarf_die_get_attr(&die, N00B_DW_AT_type);
        if (tattr) {
            const char *base = resolve_type_name(info, cu, table, tattr->u64);
            size_t      len  = strlen(base);
            char       *buf  = n00b_alloc_array(char, len + 7);
            memcpy(buf, "const ", 6);
            memcpy(buf + 6, base, len + 1);
            return buf;
        }
        return "const void";
    }

    case N00B_DW_TAG_volatile_type: {
        const n00b_dwarf_attr_t *tattr =
            n00b_dwarf_die_get_attr(&die, N00B_DW_AT_type);
        if (tattr) {
            const char *base = resolve_type_name(info, cu, table, tattr->u64);
            size_t      len  = strlen(base);
            char       *buf  = n00b_alloc_array(char, len + 10);
            memcpy(buf, "volatile ", 9);
            memcpy(buf + 9, base, len + 1);
            return buf;
        }
        return "volatile void";
    }

    case N00B_DW_TAG_restrict_type: {
        const n00b_dwarf_attr_t *tattr =
            n00b_dwarf_die_get_attr(&die, N00B_DW_AT_type);
        if (tattr) {
            const char *base = resolve_type_name(info, cu, table, tattr->u64);
            size_t      len  = strlen(base);
            char       *buf  = n00b_alloc_array(char, len + 11);
            memcpy(buf, "restrict ", 9);
            memcpy(buf + 9, base, len + 1);
            return buf;
        }
        return "restrict void";
    }

    case N00B_DW_TAG_reference_type:
    case N00B_DW_TAG_rvalue_reference_type: {
        const n00b_dwarf_attr_t *tattr =
            n00b_dwarf_die_get_attr(&die, N00B_DW_AT_type);
        if (tattr) {
            const char *base = resolve_type_name(info, cu, table, tattr->u64);
            size_t      len  = strlen(base);
            char       *buf  = n00b_alloc_array(char, len + 3);
            memcpy(buf, base, len);
            buf[len]     = ' ';
            buf[len + 1] = '&';
            buf[len + 2] = '\0';
            return buf;
        }
        return "void &";
    }

    case N00B_DW_TAG_array_type: {
        const n00b_dwarf_attr_t *tattr =
            n00b_dwarf_die_get_attr(&die, N00B_DW_AT_type);
        if (tattr) {
            const char *base = resolve_type_name(info, cu, table, tattr->u64);
            size_t      len  = strlen(base);
            char       *buf  = n00b_alloc_array(char, len + 3);
            memcpy(buf, base, len);
            buf[len]     = '[';
            buf[len + 1] = ']';
            buf[len + 2] = '\0';
            return buf;
        }
        return "?[]";
    }

    case N00B_DW_TAG_subroutine_type:
        return "func";

    default:
        return name_attr ? name_attr->str : "?";
    }
}

/// Find which CU contains a given .debug_info offset.
static n00b_dwarf_cu_t *
find_cu_for_offset(n00b_dwarf_info_t *info, size_t offset)
{
    for (size_t i = 0; i < info->num_cus; i++) {
        n00b_dwarf_cu_t *cu = &info->cus[i];
        size_t initial_size = cu->is_64bit ? 12 : 4;
        size_t cu_end       = cu->cu_offset + initial_size + cu->unit_length;
        if (offset >= cu->cu_offset && offset < cu_end) {
            return cu;
        }
    }
    return nullptr;
}

// ============================================================================
// Function index
// ============================================================================

void
n00b_dwarf_build_func_index(n00b_dwarf_info_t *info)
{
    if (!info || info->func_index_built) {
        return;
    }
    info->func_index_built = true;

    size_t func_cap = 64;
    size_t func_count = 0;
    n00b_dwarf_function_t *funcs =
        n00b_alloc_array(n00b_dwarf_function_t, func_cap);

    for (size_t ci = 0; ci < info->num_cus; ci++) {
        n00b_dwarf_cu_t *cu = &info->cus[ci];
        n00b_dwarf_abbrev_table_t *table = query_get_abbrev(info, cu);
        if (!table) {
            continue;
        }

        size_t initial_size = cu->is_64bit ? 12 : 4;
        size_t cu_end = cu->cu_offset + initial_size + cu->unit_length;

        // Get the source file name from the CU root DIE.
        const char *cu_file = nullptr;
        {
            n00b_dwarf_die_t root = {0};
            if (n00b_dwarf_parse_die(info, table, cu, cu->die_offset, &root)) {
                const n00b_dwarf_attr_t *na =
                    n00b_dwarf_die_get_attr(&root, N00B_DW_AT_name);
                if (na) {
                    cu_file = na->str;
                }
            }
        }

        // Walk all DIEs in the CU looking for subprograms.
        size_t pos = cu->die_offset;
        while (pos < cu_end) {
            n00b_dwarf_die_t die = {0};
            if (!n00b_dwarf_parse_die(info, table, cu, pos, &die)) {
                break;
            }

            if (die.tag == 0) {
                // Null DIE.
                pos = die.next_offset;
                continue;
            }

            if (die.tag == N00B_DW_TAG_subprogram) {
                const n00b_dwarf_attr_t *name_a =
                    n00b_dwarf_die_get_attr(&die, N00B_DW_AT_name);
                const n00b_dwarf_attr_t *link_a =
                    n00b_dwarf_die_get_attr(&die, N00B_DW_AT_linkage_name);
                const n00b_dwarf_attr_t *low_a =
                    n00b_dwarf_die_get_attr(&die, N00B_DW_AT_low_pc);
                const n00b_dwarf_attr_t *high_a =
                    n00b_dwarf_die_get_attr(&die, N00B_DW_AT_high_pc);
                const n00b_dwarf_attr_t *ext_a =
                    n00b_dwarf_die_get_attr(&die, N00B_DW_AT_external);
                const n00b_dwarf_attr_t *line_a =
                    n00b_dwarf_die_get_attr(&die, N00B_DW_AT_decl_line);

                if (name_a || link_a) {
                    if (func_count >= func_cap) {
                        func_cap *= 2;
                        n00b_dwarf_function_t *nf =
                            n00b_alloc_array(n00b_dwarf_function_t, func_cap);
                        memcpy(nf, funcs, func_count * sizeof(*nf));
                        funcs = nf;
                    }

                    n00b_dwarf_function_t *f = &funcs[func_count];
                    memset(f, 0, sizeof(*f));

                    if (name_a && name_a->str) {
                        f->name = n00b_string_from_cstr(name_a->str);
                    }
                    if (link_a && link_a->str) {
                        f->linkage_name =
                            n00b_string_from_cstr(link_a->str);
                    }
                    if (low_a) {
                        f->low_pc = low_a->u64;
                    }
                    if (high_a) {
                        // high_pc: if form is addr, it's absolute;
                        // otherwise it's an offset from low_pc.
                        if (high_a->form == N00B_DW_FORM_addr) {
                            f->high_pc = high_a->u64;
                        } else {
                            f->high_pc = f->low_pc + high_a->u64;
                        }
                    }
                    f->is_external = (ext_a && ext_a->u64);
                    if (line_a) {
                        f->source_line = (uint32_t)line_a->u64;
                    }
                    if (cu_file) {
                        f->source_file =
                            n00b_string_from_cstr(cu_file);
                    }

                    // Extract parameters from child DIEs.
                    if (die.has_children) {
                        size_t param_cap   = 8;
                        size_t param_count = 0;
                        n00b_string_t **pnames =
                            n00b_alloc_array(n00b_string_t *, param_cap);
                        n00b_string_t **ptypes =
                            n00b_alloc_array(n00b_string_t *, param_cap);

                        size_t child_pos = die.next_offset;
                        while (child_pos < cu_end) {
                            n00b_dwarf_die_t child = {0};
                            if (!n00b_dwarf_parse_die(info, table, cu,
                                                      child_pos, &child)) {
                                break;
                            }
                            if (child.tag == 0) {
                                break;  // End of children.
                            }

                            if (child.tag == N00B_DW_TAG_formal_parameter) {
                                // Skip artificial parameters (like 'this').
                                const n00b_dwarf_attr_t *art =
                                    n00b_dwarf_die_get_attr(&child,
                                                            N00B_DW_AT_artificial);
                                if (art && art->u64) {
                                    child_pos = child.next_offset;
                                    continue;
                                }

                                if (param_count >= param_cap) {
                                    param_cap *= 2;
                                    n00b_string_t **nn =
                                        n00b_alloc_array(n00b_string_t *, param_cap);
                                    memcpy(nn, pnames,
                                           param_count * sizeof(n00b_string_t *));
                                    pnames = nn;
                                    n00b_string_t **nt =
                                        n00b_alloc_array(n00b_string_t *, param_cap);
                                    memcpy(nt, ptypes,
                                           param_count * sizeof(n00b_string_t *));
                                    ptypes = nt;
                                }

                                const n00b_dwarf_attr_t *pn =
                                    n00b_dwarf_die_get_attr(&child,
                                                            N00B_DW_AT_name);
                                if (pn && pn->str) {
                                    pnames[param_count] =
                                        n00b_string_from_cstr(pn->str);
                                } else {
                                    char syn[16];
                                    snprintf(syn, sizeof(syn), "p%zu",
                                             param_count);
                                    pnames[param_count] =
                                        n00b_string_from_cstr(syn);
                                }

                                const n00b_dwarf_attr_t *pt =
                                    n00b_dwarf_die_get_attr(&child,
                                                            N00B_DW_AT_type);
                                if (pt) {
                                    const char *tname =
                                        resolve_type_name(info, cu, table,
                                                          pt->u64);
                                    ptypes[param_count] =
                                        n00b_string_from_cstr(tname);
                                } else {
                                    ptypes[param_count] =
                                        r"?";
                                }
                                param_count++;
                            }

                            child_pos = child.next_offset;
                        }

                        f->param_names = pnames;
                        f->param_types = ptypes;
                        f->param_count = param_count;
                    }

                    // Return type.
                    const n00b_dwarf_attr_t *ret_a =
                        n00b_dwarf_die_get_attr(&die, N00B_DW_AT_type);
                    if (ret_a) {
                        const char *rname =
                            resolve_type_name(info, cu, table, ret_a->u64);
                        f->return_type =
                            n00b_string_from_cstr(rname);
                    } else {
                        f->return_type =
                            r"void";
                    }

                    func_count++;
                }
            }

            // Advance: if has_children, descend into children.
            // (We parse all children linearly, not just top-level.)
            pos = die.next_offset;
        }
    }

    info->functions     = funcs;
    info->num_functions = func_count;
}

// ============================================================================
// Function queries
// ============================================================================

n00b_dwarf_function_t *
n00b_dwarf_function_at_addr(n00b_dwarf_info_t *info, uint64_t addr)
{
    if (!info) {
        return nullptr;
    }
    if (!info->func_index_built) {
        n00b_dwarf_build_func_index(info);
    }

    for (size_t i = 0; i < info->num_functions; i++) {
        n00b_dwarf_function_t *f = &info->functions[i];
        if (f->low_pc != 0 && f->high_pc != 0) {
            if (addr >= f->low_pc && addr < f->high_pc) {
                return f;
            }
        } else if (f->low_pc != 0 && addr == f->low_pc) {
            return f;
        }
    }
    return nullptr;
}

n00b_dwarf_function_t *
n00b_dwarf_function_by_name(n00b_dwarf_info_t *info, const char *name)
{
    if (!info || !name) {
        return nullptr;
    }
    if (!info->func_index_built) {
        n00b_dwarf_build_func_index(info);
    }

    for (size_t i = 0; i < info->num_functions; i++) {
        n00b_dwarf_function_t *f = &info->functions[i];
        // Try linkage name first.
        if (f->linkage_name && strcmp(f->linkage_name->data, name) == 0) {
            return f;
        }
        if (f->name && strcmp(f->name->data, name) == 0) {
            return f;
        }
        // macOS convention: leading underscore.
        if (name[0] == '_') {
            if (f->linkage_name
                && strcmp(f->linkage_name->data, name + 1) == 0) {
                return f;
            }
            if (f->name && strcmp(f->name->data, name + 1) == 0) {
                return f;
            }
        }
    }
    return nullptr;
}

// ============================================================================
// Type index
// ============================================================================

/// Map N00B_DW_ATE encoding + byte_size to a C type name.
static const char *
base_type_name(uint64_t encoding, uint64_t byte_size)
{
    switch (encoding) {
    case N00B_DW_ATE_boolean:
        return "bool";
    case N00B_DW_ATE_signed_char:
        return (byte_size == 1) ? "char" : "signed char";
    case N00B_DW_ATE_unsigned_char:
        return (byte_size == 1) ? "unsigned char" : "unsigned char";
    case N00B_DW_ATE_signed:
        switch (byte_size) {
        case 1:  return "int8_t";
        case 2:  return "int16_t";
        case 4:  return "int32_t";
        case 8:  return "int64_t";
        default: return "int";
        }
    case N00B_DW_ATE_unsigned:
        switch (byte_size) {
        case 1:  return "uint8_t";
        case 2:  return "uint16_t";
        case 4:  return "uint32_t";
        case 8:  return "uint64_t";
        default: return "unsigned int";
        }
    case N00B_DW_ATE_float:
        switch (byte_size) {
        case 4:  return "float";
        case 8:  return "double";
        case 16: return "long double";
        default: return "float";
        }
    case N00B_DW_ATE_address:
        return "void *";
    case N00B_DW_ATE_UTF:
        switch (byte_size) {
        case 1:  return "char";
        case 2:  return "char16_t";
        case 4:  return "char32_t";
        default: return "char";
        }
    default:
        return "?";
    }
}

/// Map N00B_DW_TAG to n00b_dwarf_type_kind_t.
static n00b_dwarf_type_kind_t
tag_to_type_kind(uint64_t tag)
{
    switch (tag) {
    case N00B_DW_TAG_structure_type: return N00B_DWARF_TYPE_STRUCT;
    case N00B_DW_TAG_class_type:     return N00B_DWARF_TYPE_CLASS;
    case N00B_DW_TAG_union_type:     return N00B_DWARF_TYPE_UNION;
    case N00B_DW_TAG_enumeration_type: return N00B_DWARF_TYPE_ENUM;
    case N00B_DW_TAG_typedef:        return N00B_DWARF_TYPE_TYPEDEF;
    case N00B_DW_TAG_array_type:     return N00B_DWARF_TYPE_ARRAY;
    case N00B_DW_TAG_pointer_type:   return N00B_DWARF_TYPE_POINTER;
    case N00B_DW_TAG_base_type:      return N00B_DWARF_TYPE_BASE;
    default:                    return N00B_DWARF_TYPE_STRUCT;
    }
}

/// Parse members of a struct/union/class DIE.
static void
parse_members(n00b_dwarf_info_t         *info,
              n00b_dwarf_cu_t           *cu,
              n00b_dwarf_abbrev_table_t *table,
              n00b_dwarf_die_t          *parent_die,
              n00b_dwarf_type_def_t     *type)
{
    if (!parent_die->has_children) {
        return;
    }

    size_t mem_cap   = 8;
    size_t mem_count = 0;
    n00b_dwarf_member_t *members =
        n00b_alloc_array(n00b_dwarf_member_t, mem_cap);

    size_t initial_size = cu->is_64bit ? 12 : 4;
    size_t cu_end = cu->cu_offset + initial_size + cu->unit_length;

    size_t pos = parent_die->next_offset;
    while (pos < cu_end) {
        n00b_dwarf_die_t child = {0};
        if (!n00b_dwarf_parse_die(info, table, cu, pos, &child)) {
            break;
        }
        if (child.tag == 0) {
            break;
        }

        if (child.tag == N00B_DW_TAG_member) {
            if (mem_count >= mem_cap) {
                mem_cap *= 2;
                n00b_dwarf_member_t *nm =
                    n00b_alloc_array(n00b_dwarf_member_t, mem_cap);
                memcpy(nm, members, mem_count * sizeof(n00b_dwarf_member_t));
                members = nm;
            }

            n00b_dwarf_member_t *m = &members[mem_count];
            memset(m, 0, sizeof(*m));

            const n00b_dwarf_attr_t *na =
                n00b_dwarf_die_get_attr(&child, N00B_DW_AT_name);
            if (na && na->str) {
                m->name = n00b_string_from_cstr(na->str);
            }

            const n00b_dwarf_attr_t *ta =
                n00b_dwarf_die_get_attr(&child, N00B_DW_AT_type);
            if (ta) {
                const char *tname =
                    resolve_type_name(info, cu, table, ta->u64);
                m->type_name = n00b_string_from_cstr(tname);
            }

            const n00b_dwarf_attr_t *loc =
                n00b_dwarf_die_get_attr(&child, N00B_DW_AT_data_member_location);
            if (loc) {
                if (loc->form == N00B_DW_FORM_exprloc
                    || loc->form == N00B_DW_FORM_block1
                    || loc->form == N00B_DW_FORM_block2
                    || loc->form == N00B_DW_FORM_block4
                    || loc->form == N00B_DW_FORM_block) {
                    // Parse N00B_DW_OP_plus_uconst.
                    if (loc->block.size >= 2
                        && loc->block.data[0] == N00B_DW_OP_plus_uconst) {
                        size_t br;
                        m->offset =
                            (uint64_t)dwarf_decode_uleb128_inline(
                                loc->block.data + 1, &br);
                    }
                } else {
                    m->offset = loc->u64;
                }
            }

            const n00b_dwarf_attr_t *bs =
                n00b_dwarf_die_get_attr(&child, N00B_DW_AT_byte_size);
            if (bs) {
                m->size = bs->u64;
            }

            const n00b_dwarf_attr_t *bsz =
                n00b_dwarf_die_get_attr(&child, N00B_DW_AT_bit_size);
            if (bsz) {
                m->bit_size = (uint32_t)bsz->u64;
            }

            const n00b_dwarf_attr_t *bo =
                n00b_dwarf_die_get_attr(&child, N00B_DW_AT_bit_offset);
            if (bo) {
                m->bit_offset = (uint32_t)bo->u64;
            } else {
                const n00b_dwarf_attr_t *dbo =
                    n00b_dwarf_die_get_attr(&child, N00B_DW_AT_data_bit_offset);
                if (dbo) {
                    m->bit_offset = (uint32_t)dbo->u64;
                }
            }

            mem_count++;
        }

        pos = child.next_offset;
    }

    type->members     = members;
    type->num_members = mem_count;
}

/// Parse enumerators of an enumeration DIE.
static void
parse_enumerators(n00b_dwarf_info_t         *info,
                  n00b_dwarf_cu_t           *cu,
                  n00b_dwarf_abbrev_table_t *table,
                  n00b_dwarf_die_t          *parent_die,
                  n00b_dwarf_type_def_t     *type)
{
    if (!parent_die->has_children) {
        return;
    }

    size_t en_cap   = 8;
    size_t en_count = 0;
    n00b_dwarf_enumerator_t *enums =
        n00b_alloc_array(n00b_dwarf_enumerator_t, en_cap);

    size_t initial_size = cu->is_64bit ? 12 : 4;
    size_t cu_end = cu->cu_offset + initial_size + cu->unit_length;

    size_t pos = parent_die->next_offset;
    while (pos < cu_end) {
        n00b_dwarf_die_t child = {0};
        if (!n00b_dwarf_parse_die(info, table, cu, pos, &child)) {
            break;
        }
        if (child.tag == 0) {
            break;
        }

        if (child.tag == N00B_DW_TAG_enumerator) {
            if (en_count >= en_cap) {
                en_cap *= 2;
                n00b_dwarf_enumerator_t *ne =
                    n00b_alloc_array(n00b_dwarf_enumerator_t, en_cap);
                memcpy(ne, enums, en_count * sizeof(n00b_dwarf_enumerator_t));
                enums = ne;
            }

            n00b_dwarf_enumerator_t *e = &enums[en_count];
            const n00b_dwarf_attr_t *na =
                n00b_dwarf_die_get_attr(&child, N00B_DW_AT_name);
            if (na && na->str) {
                e->name = n00b_string_from_cstr(na->str);
            } else {
                char syn[16];
                snprintf(syn, sizeof(syn), "ENUM_%zu", en_count);
                e->name = n00b_string_from_cstr(syn);
            }

            const n00b_dwarf_attr_t *cv =
                n00b_dwarf_die_get_attr(&child, N00B_DW_AT_const_value);
            if (cv) {
                if (cv->form == N00B_DW_FORM_sdata) {
                    e->value = cv->s64;
                } else {
                    e->value = (int64_t)cv->u64;
                }
            }

            en_count++;
        }

        pos = child.next_offset;
    }

    type->enumerators     = enums;
    type->num_enumerators = en_count;
}

void
n00b_dwarf_build_type_index(n00b_dwarf_info_t *info)
{
    if (!info || info->type_index_built) {
        return;
    }
    info->type_index_built = true;

    size_t type_cap   = 64;
    size_t type_count = 0;
    n00b_dwarf_type_def_t *types =
        n00b_alloc_array(n00b_dwarf_type_def_t, type_cap);

    for (size_t ci = 0; ci < info->num_cus; ci++) {
        n00b_dwarf_cu_t *cu = &info->cus[ci];
        n00b_dwarf_abbrev_table_t *table = query_get_abbrev(info, cu);
        if (!table) {
            continue;
        }

        size_t initial_size = cu->is_64bit ? 12 : 4;
        size_t cu_end = cu->cu_offset + initial_size + cu->unit_length;

        size_t pos = cu->die_offset;
        while (pos < cu_end) {
            n00b_dwarf_die_t die = {0};
            if (!n00b_dwarf_parse_die(info, table, cu, pos, &die)) {
                break;
            }
            if (die.tag == 0) {
                pos = die.next_offset;
                continue;
            }

            bool is_type_tag = (die.tag == N00B_DW_TAG_structure_type
                             || die.tag == N00B_DW_TAG_class_type
                             || die.tag == N00B_DW_TAG_union_type
                             || die.tag == N00B_DW_TAG_enumeration_type
                             || die.tag == N00B_DW_TAG_typedef
                             || die.tag == N00B_DW_TAG_base_type);

            if (is_type_tag) {
                const n00b_dwarf_attr_t *name_a =
                    n00b_dwarf_die_get_attr(&die, N00B_DW_AT_name);

                // Skip anonymous types and forward declarations
                // without a name.
                if (!name_a || !name_a->str || name_a->str[0] == '\0') {
                    const n00b_dwarf_attr_t *decl =
                        n00b_dwarf_die_get_attr(&die, N00B_DW_AT_declaration);
                    if (decl && decl->u64) {
                        pos = die.next_offset;
                        continue;
                    }
                    if (!name_a) {
                        pos = die.next_offset;
                        continue;
                    }
                }

                // Check for duplicates — prefer types with more detail.
                bool dup = false;
                if (name_a && name_a->str) {
                    for (size_t ti = 0; ti < type_count; ti++) {
                        if (types[ti].name
                            && strcmp(types[ti].name->data,
                                      name_a->str) == 0) {
                            dup = true;
                            break;
                        }
                    }
                }
                if (dup) {
                    pos = die.next_offset;
                    continue;
                }

                if (type_count >= type_cap) {
                    type_cap *= 2;
                    n00b_dwarf_type_def_t *nt =
                        n00b_alloc_array(n00b_dwarf_type_def_t, type_cap);
                    memcpy(nt, types,
                           type_count * sizeof(n00b_dwarf_type_def_t));
                    types = nt;
                }

                n00b_dwarf_type_def_t *t = &types[type_count];
                memset(t, 0, sizeof(*t));
                t->kind       = tag_to_type_kind(die.tag);
                t->die_offset = die.offset;

                if (name_a && name_a->str) {
                    t->name = n00b_string_from_cstr(name_a->str);
                }

                const n00b_dwarf_attr_t *bs =
                    n00b_dwarf_die_get_attr(&die, N00B_DW_AT_byte_size);
                if (bs) {
                    t->byte_size = bs->u64;
                }

                const n00b_dwarf_attr_t *al =
                    n00b_dwarf_die_get_attr(&die, N00B_DW_AT_alignment);
                if (al) {
                    t->alignment = al->u64;
                }

                const n00b_dwarf_attr_t *enc =
                    n00b_dwarf_die_get_attr(&die, N00B_DW_AT_encoding);
                if (enc) {
                    t->encoding = enc->u64;
                }

                // Parse members for struct/union/class.
                if (die.tag == N00B_DW_TAG_structure_type
                    || die.tag == N00B_DW_TAG_class_type
                    || die.tag == N00B_DW_TAG_union_type) {
                    parse_members(info, cu, table, &die, t);
                }

                // Parse enumerators.
                if (die.tag == N00B_DW_TAG_enumeration_type) {
                    parse_enumerators(info, cu, table, &die, t);
                }

                // Typedef target.
                if (die.tag == N00B_DW_TAG_typedef) {
                    const n00b_dwarf_attr_t *ta =
                        n00b_dwarf_die_get_attr(&die, N00B_DW_AT_type);
                    if (ta) {
                        const char *tname =
                            resolve_type_name(info, cu, table, ta->u64);
                        t->aliased_type =
                            n00b_string_from_cstr(tname);
                    }
                }

                type_count++;
            }

            pos = die.next_offset;
        }
    }

    info->types     = types;
    info->num_types = type_count;
}

// ============================================================================
// Type queries
// ============================================================================

n00b_dwarf_type_def_t *
n00b_dwarf_type_by_name(n00b_dwarf_info_t *info, const char *name)
{
    if (!info || !name) {
        return nullptr;
    }
    if (!info->type_index_built) {
        n00b_dwarf_build_type_index(info);
    }

    for (size_t i = 0; i < info->num_types; i++) {
        if (info->types[i].name
            && strcmp(info->types[i].name->data, name) == 0) {
            return &info->types[i];
        }
    }
    return nullptr;
}

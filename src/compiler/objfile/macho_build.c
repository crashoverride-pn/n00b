#include <string.h>

#include "compiler/objfile/macho_build.h"
#include "compiler/objfile/macho_fat_rewrite.h"
#include "internal/compiler/objfile/macho_fat_rewrite_internal.h"

// ============================================================================
// Constants
// ============================================================================

#define N00B_MACHO_PAGE_SIZE  0x4000  // 16K pages (arm64 / modern x86_64)
#define N00B_MACHO_HDR_SIZE   32      // sizeof(n00b_macho_header64_t)
#define N00B_MACHO_SEG_CMD    72      // sizeof(n00b_macho_segment_command64_t)
#define N00B_MACHO_SECT_SIZE  80      // sizeof(n00b_macho_section64_t)
#define N00B_MACHO_NLIST_SIZE 16      // sizeof(n00b_macho_nlist64_t)

// ============================================================================
// Alignment helpers
// ============================================================================

static inline size_t
align_up(size_t v, size_t align)
{
    if (align <= 1) return v;
    return (v + align - 1) & ~(align - 1);
}

static inline size_t
pad_to_8(size_t v)
{
    return align_up(v, 8);
}

// ============================================================================
// Rebase opcode encoder
// ============================================================================

static void
encode_rebase_opcodes(n00b_writer_t *w, n00b_macho_binary_t *bin)
{
    if (bin->num_rebases == 0) return;

    // The segment_index in rebase entries uses the output binary's numbering,
    // which includes __PAGEZERO at index 0 for MH_EXECUTE.  bin->segments[]
    // does NOT include __PAGEZERO, so we subtract the pagezero offset.
    uint8_t  pz_off     = (bin->header.filetype == MH_EXECUTE) ? 1 : 0;

    uint8_t  cur_type    = 0;
    uint8_t  cur_seg     = 0xFF;
    uint64_t cur_offset  = 0;  // segment-relative offset

    for (uint32_t i = 0; i < bin->num_rebases; i++) {
        n00b_macho_rebase_t *r = &bin->rebases[i];

        // Convert absolute address to segment-relative offset.
        uint8_t  user_idx = (r->segment_index >= pz_off)
                          ? r->segment_index - pz_off : 0;
        uint64_t seg_base = (user_idx < bin->num_segments)
                          ? bin->segments[user_idx].vmaddr
                          : 0;
        uint64_t seg_off  = r->address - seg_base;

        if (r->type != cur_type) {
            n00b_writer_write_u8(w, REBASE_OPCODE_SET_TYPE_IMM | r->type);
            cur_type = r->type;
        }

        if (r->segment_index != cur_seg) {
            n00b_writer_write_u8(w,
                REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | r->segment_index);
            n00b_writer_write_uleb128(w, seg_off);
            cur_seg    = r->segment_index;
            cur_offset = seg_off;
        }
        else if (seg_off != cur_offset) {
            int64_t delta = (int64_t)(seg_off - cur_offset);

            if (delta > 0) {
                n00b_writer_write_u8(w, REBASE_OPCODE_ADD_ADDR_ULEB);
                n00b_writer_write_uleb128(w, (uint64_t)delta);
            }
            else {
                n00b_writer_write_u8(w,
                    REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
                    | r->segment_index);
                n00b_writer_write_uleb128(w, seg_off);
            }

            cur_offset = seg_off;
        }

        n00b_writer_write_u8(w, REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1);
        cur_offset += 8;
    }

    n00b_writer_write_u8(w, REBASE_OPCODE_DONE);
}

// ============================================================================
// Bind opcode encoder
// ============================================================================

static void
encode_bind_opcodes(n00b_writer_t *w, n00b_macho_binary_t *bin,
                    n00b_macho_binding_t *bindings,
                    uint32_t count, bool lazy)
{
    uint8_t pz_off = (bin->header.filetype == MH_EXECUTE) ? 1 : 0;

    for (uint32_t i = 0; i < count; i++) {
        n00b_macho_binding_t *b = &bindings[i];

        // Set dylib ordinal.
        if (b->library_ordinal > 0 && b->library_ordinal <= 15) {
            n00b_writer_write_u8(w,
                BIND_OPCODE_SET_DYLIB_ORDINAL_IMM
                | (uint8_t)b->library_ordinal);
        }
        else if (b->library_ordinal > 15) {
            n00b_writer_write_u8(w, BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB);
            n00b_writer_write_uleb128(w, (uint64_t)b->library_ordinal);
        }
        else {
            // Special ordinal (0, -1, -2, -3).
            uint8_t imm = (uint8_t)(b->library_ordinal & BIND_IMMEDIATE_MASK);
            n00b_writer_write_u8(w,
                BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | imm);
        }

        // Set symbol name.
        if (b->symbol_name && b->symbol_name->data) {
            uint8_t flags = b->is_weak ? 0x01 : 0x00;
            n00b_writer_write_u8(w,
                BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | flags);
            n00b_writer_write_cstring(w, b->symbol_name->data);
        }

        // Set type.
        n00b_writer_write_u8(w, BIND_OPCODE_SET_TYPE_IMM | b->type);

        // Set addend if non-zero.
        if (b->addend != 0) {
            n00b_writer_write_u8(w, BIND_OPCODE_SET_ADDEND_SLEB);
            n00b_writer_write_sleb128(w, b->addend);
        }

        // Set segment and offset (convert absolute address to seg-relative).
        uint8_t  user_idx = (b->segment_index >= pz_off)
                          ? b->segment_index - pz_off : 0;
        uint64_t seg_base = (user_idx < bin->num_segments)
                          ? bin->segments[user_idx].vmaddr
                          : 0;
        uint64_t seg_off  = b->address - seg_base;

        n00b_writer_write_u8(w,
            BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | b->segment_index);
        n00b_writer_write_uleb128(w, seg_off);

        // Do bind.
        n00b_writer_write_u8(w, BIND_OPCODE_DO_BIND);

        if (lazy) {
            n00b_writer_write_u8(w, BIND_OPCODE_DONE);
        }
    }

    if (!lazy) {
        n00b_writer_write_u8(w, BIND_OPCODE_DONE);
    }
}

// ============================================================================
// Export trie encoder
// ============================================================================

// Trie node for building.
typedef struct trie_node {
    char              edge[256];   // Edge label from parent.
    uint64_t          flags;
    uint64_t          address;
    bool              is_terminal;
    struct trie_node *children[256];
    uint32_t          num_children;
    size_t            offset;      // Computed offset in output.
    size_t            size;        // Computed size.
} trie_node_t;

static trie_node_t *
trie_node_new(void)
{
    trie_node_t *n = n00b_alloc(trie_node_t);
    memset(n, 0, sizeof(*n));
    return n;
}

static void
trie_insert(trie_node_t *root, const char *name, uint64_t flags,
            uint64_t address)
{
    trie_node_t *node = root;

    while (*name) {
        bool found = false;

        for (uint32_t i = 0; i < node->num_children; i++) {
            if (node->children[i]->edge[0] == *name) {
                // Check how much of the edge matches.
                const char *edge = node->children[i]->edge;
                size_t elen = strlen(edge);
                size_t match = 0;

                while (match < elen && name[match] == edge[match]) {
                    match++;
                }

                if (match == elen) {
                    // Full edge match, continue down.
                    node = node->children[i];
                    name += match;
                    found = true;
                    break;
                }
                else {
                    // Partial match — split edge.
                    trie_node_t *split = trie_node_new();
                    memcpy(split->edge, edge, match);
                    split->edge[match] = '\0';

                    // Adjust old child's edge.
                    trie_node_t *old_child = node->children[i];
                    memmove(old_child->edge, old_child->edge + match,
                            strlen(old_child->edge + match) + 1);

                    split->children[0]  = old_child;
                    split->num_children = 1;
                    node->children[i]   = split;

                    node = split;
                    name += match;
                    found = true;
                    break;
                }
            }
        }

        if (!found) {
            // Create new child with remaining string as edge.
            trie_node_t *child = trie_node_new();
            strncpy(child->edge, name, 255);
            child->edge[255] = '\0';

            child->is_terminal = true;
            child->flags       = flags;
            child->address     = address;

            node->children[node->num_children++] = child;
            return;
        }
    }

    node->is_terminal = true;
    node->flags       = flags;
    node->address     = address;
}

static size_t
uleb128_size(uint64_t v)
{
    size_t n = 0;

    do {
        v >>= 7;
        n++;
    } while (v != 0);

    return n;
}

// Compute the size of a trie node for serialization.
static size_t
trie_node_size(trie_node_t *node)
{
    size_t size = 0;

    // Terminal info.
    if (node->is_terminal) {
        size_t terminal_size = uleb128_size(node->flags)
                             + uleb128_size(node->address);
        size += uleb128_size(terminal_size) + terminal_size;
    }
    else {
        size += 1; // terminal_size = 0
    }

    // Number of children.
    size += 1; // uint8_t num_children

    // Each child: edge label (cstring) + child offset (uleb128).
    for (uint32_t i = 0; i < node->num_children; i++) {
        size += strlen(node->children[i]->edge) + 1; // edge + NUL
        size += uleb128_size(node->children[i]->offset);
    }

    return size;
}

// Compute offsets for all nodes (two-pass).
static size_t
trie_compute_offsets(trie_node_t *node, size_t offset)
{
    node->offset = offset;
    node->size   = trie_node_size(node);
    offset += node->size;

    for (uint32_t i = 0; i < node->num_children; i++) {
        offset = trie_compute_offsets(node->children[i], offset);
    }

    return offset;
}

static void
trie_write(n00b_writer_t *w, trie_node_t *node)
{
    // Terminal info.
    if (node->is_terminal) {
        size_t terminal_size = uleb128_size(node->flags)
                             + uleb128_size(node->address);
        n00b_writer_write_uleb128(w, terminal_size);
        n00b_writer_write_uleb128(w, node->flags);
        n00b_writer_write_uleb128(w, node->address);
    }
    else {
        n00b_writer_write_u8(w, 0);
    }

    n00b_writer_write_u8(w, (uint8_t)node->num_children);

    for (uint32_t i = 0; i < node->num_children; i++) {
        n00b_writer_write_cstring(w, node->children[i]->edge);
        n00b_writer_write_uleb128(w, node->children[i]->offset);
    }

    for (uint32_t i = 0; i < node->num_children; i++) {
        trie_write(w, node->children[i]);
    }
}

static size_t
encode_export_trie(n00b_writer_t *w, n00b_macho_binary_t *bin)
{
    if (bin->num_exports == 0) return 0;

    trie_node_t *root = trie_node_new();

    for (uint32_t i = 0; i < bin->num_exports; i++) {
        n00b_macho_export_t *e = &bin->exports[i];

        if (e->name && e->name->data) {
            trie_insert(root, e->name->data, e->flags, e->address);
        }
    }

    // Two-pass: compute sizes, fix offsets.
    size_t total = trie_compute_offsets(root, 0);

    // Second pass to fix child offset references (since first pass
    // children don't have their offsets yet when parent is computed).
    // Re-compute after all offsets are known.
    trie_compute_offsets(root, 0);

    size_t start = n00b_writer_pos(w);
    trie_write(w, root);

    return n00b_writer_pos(w) - start;
    (void)total;
}

// ============================================================================
// Function starts encoder
// ============================================================================

static size_t
encode_function_starts(n00b_writer_t *w, n00b_macho_binary_t *bin,
                       uint64_t text_vmaddr)
{
    if (!bin->function_starts || bin->function_starts->count == 0) return 0;

    size_t start = n00b_writer_pos(w);
    uint64_t prev = text_vmaddr;

    for (uint32_t i = 0; i < bin->function_starts->count; i++) {
        uint64_t addr = bin->function_starts->addresses[i];
        uint64_t delta = addr - prev;
        n00b_writer_write_uleb128(w, delta);
        prev = addr;
    }

    n00b_writer_write_u8(w, 0); // terminator

    return n00b_writer_pos(w) - start;
}

// ============================================================================
// Symbol sorting (locals → extdefs → undefs)
// ============================================================================

typedef struct {
    uint32_t orig_index;
    uint8_t  category; // 0=local, 1=extdef, 2=undef
} sym_sort_entry_t;

static int
sym_compare(const void *a, const void *b)
{
    const sym_sort_entry_t *sa = a;
    const sym_sort_entry_t *sb = b;

    if (sa->category != sb->category) {
        return (int)sa->category - (int)sb->category;
    }

    return (int)sa->orig_index - (int)sb->orig_index;
}

static void
sort_symbols(n00b_macho_symbol_t *syms, uint32_t nsyms,
             uint32_t *out_nlocal, uint32_t *out_nextdef, uint32_t *out_nundef)
{
    *out_nlocal  = 0;
    *out_nextdef = 0;
    *out_nundef  = 0;

    if (nsyms == 0) return;

    sym_sort_entry_t *entries = n00b_alloc_array(sym_sort_entry_t, nsyms);

    for (uint32_t i = 0; i < nsyms; i++) {
        entries[i].orig_index = i;
        uint8_t type = syms[i].type;

        if ((type & N_EXT) == 0) {
            entries[i].category = 0; // local
        }
        else if ((type & N_TYPE) == N_UNDF) {
            entries[i].category = 2; // undef
        }
        else {
            entries[i].category = 1; // extdef
        }
    }

    // Sort.
    // Use a simple insertion sort since counts are typically small.
    for (uint32_t i = 1; i < nsyms; i++) {
        sym_sort_entry_t tmp = entries[i];
        uint32_t j = i;

        while (j > 0 && sym_compare(&tmp, &entries[j - 1]) < 0) {
            entries[j] = entries[j - 1];
            j--;
        }

        entries[j] = tmp;
    }

    // Reorder symbols in place.
    n00b_macho_symbol_t *sorted = n00b_alloc_array(n00b_macho_symbol_t, nsyms);

    for (uint32_t i = 0; i < nsyms; i++) {
        sorted[i] = syms[entries[i].orig_index];

        switch (entries[i].category) {
        case 0: (*out_nlocal)++;  break;
        case 1: (*out_nextdef)++; break;
        case 2: (*out_nundef)++;  break;
        }
    }

    memcpy(syms, sorted, nsyms * sizeof(n00b_macho_symbol_t));
}

// ============================================================================
// Write helpers
// ============================================================================

static void
write_segment_command(n00b_writer_t *w, const char *name, uint64_t vmaddr,
                      uint64_t vmsize, uint64_t fileoff, uint64_t filesize,
                      uint32_t maxprot, uint32_t initprot, uint32_t nsects,
                      uint32_t flags)
{
    uint32_t cmdsize = N00B_MACHO_SEG_CMD + nsects * N00B_MACHO_SECT_SIZE;

    n00b_writer_write_u32(w, LC_SEGMENT_64);
    n00b_writer_write_u32(w, cmdsize);

    // segname[16]
    char segname[16] = {0};

    if (name) {
        strncpy(segname, name, 16);
    }

    n00b_writer_write_bytes(w, segname, 16);
    n00b_writer_write_u64(w, vmaddr);
    n00b_writer_write_u64(w, vmsize);
    n00b_writer_write_u64(w, fileoff);
    n00b_writer_write_u64(w, filesize);
    n00b_writer_write_u32(w, maxprot);
    n00b_writer_write_u32(w, initprot);
    n00b_writer_write_u32(w, nsects);
    n00b_writer_write_u32(w, flags);
}

static void
write_section_header(n00b_writer_t *w, n00b_macho_section_t *sec)
{
    char sectname[16] = {0};
    char segname[16]  = {0};

    strncpy(sectname, sec->sectname, 16);
    strncpy(segname, sec->segname, 16);

    n00b_writer_write_bytes(w, sectname, 16);
    n00b_writer_write_bytes(w, segname, 16);
    n00b_writer_write_u64(w, sec->addr);
    n00b_writer_write_u64(w, sec->size);
    n00b_writer_write_u32(w, sec->offset);
    n00b_writer_write_u32(w, sec->align);
    n00b_writer_write_u32(w, sec->reloff);
    n00b_writer_write_u32(w, sec->nreloc);
    n00b_writer_write_u32(w, sec->flags);
    n00b_writer_write_u32(w, sec->reserved1);
    n00b_writer_write_u32(w, sec->reserved2);
    n00b_writer_write_u32(w, sec->reserved3);
}

// ============================================================================
// Main build function
// ============================================================================

n00b_result_t(n00b_buffer_t *)
n00b_macho_build(n00b_macho_binary_t *bin)
{
    if (!bin) {
        return n00b_result_err(n00b_buffer_t *, N00B_ERR_BUILD);
    }

    // Export + symbol parsing are lazy; materialize them before we read
    // num_exports/exports[] (dyld-info detection + export-trie re-encode) and
    // num_symbols/symbols[] (symtab re-encode) below.
    n00b_macho_ensure_exports(bin);
    n00b_macho_ensure_symbols(bin);

    // -----------------------------------------------------------------------
    // 1. Sort symbols
    // -----------------------------------------------------------------------

    uint32_t nlocal = 0, nextdef = 0, nundef = 0;

    if (bin->num_symbols > 0) {
        sort_symbols(bin->symbols, bin->num_symbols,
                     &nlocal, &nextdef, &nundef);
    }

    // -----------------------------------------------------------------------
    // 2. Build string table
    // -----------------------------------------------------------------------

    n00b_strtab_builder_t *strtab = n00b_strtab_builder_new();

    uint32_t *sym_name_offs = nullptr;

    if (bin->num_symbols > 0) {
        sym_name_offs = n00b_alloc_array(uint32_t, bin->num_symbols);

        for (uint32_t i = 0; i < bin->num_symbols; i++) {
            if (bin->symbols[i].name && bin->symbols[i].name->data) {
                sym_name_offs[i] = n00b_strtab_builder_add(
                    strtab, bin->symbols[i].name->data);
            }
        }
    }

    // -----------------------------------------------------------------------
    // 3. Determine what load commands we need
    // -----------------------------------------------------------------------

    bool has_pagezero  = (bin->header.filetype == MH_EXECUTE);
    bool has_text      = false;
    // __LINKEDIT is ALWAYS emitted, even when empty. Real-world
    // clang/ld output always includes a __LINKEDIT segment, and
    // downstream consumers (notably libchalk's add_note path which
    // needs a __LINKEDIT to grow the chalk note into) depend on
    // its presence. An empty __LINKEDIT has filesize=0 and vmsize=0
    // and adds no observable behavior change for symbol-less builds
    // beyond a single 72-byte LC_SEGMENT_64 command.
    bool has_linkedit  = true;
    (void)0;  // (the prior gating predicate kept as a comment for
              //  future readers — see git history if you need the
              //  exact symbol-count/binding-count/etc. predicate.)
    bool has_symtab    = bin->num_symbols > 0;
    bool has_main      = bin->entrypoint != 0;
    bool has_dylinker  = bin->dylinker && bin->dylinker->data && bin->dylinker->u8_bytes > 0;
    bool has_uuid      = false;
    bool has_chained   = (bin->chained_fixups && bin->chained_fixups->raw_data
                          && n00b_buffer_len(bin->chained_fixups->raw_data) > 0);
    bool has_dyld_info = !has_chained
                          && (bin->num_bindings > 0 || bin->num_rebases > 0
                              || bin->num_exports > 0);
    bool has_dysymtab  = has_symtab;
    bool has_func_starts = (bin->function_starts
                            && bin->function_starts->count > 0);
    bool has_code_sig  = (bin->code_signature && bin->code_signature->data);
    bool has_src_ver   = (bin->source_version != 0);
    bool has_build_ver = (bin->build_version != nullptr);
    bool has_ver_min   = (bin->version_min != nullptr);
    bool has_data_in_code = (bin->data_in_code
                              && bin->data_in_code->count > 0);
    bool has_enc_info  = (bin->encryption_info != nullptr);

    // Check for non-zero UUID.
    for (int i = 0; i < 16; i++) {
        if (bin->uuid[i] != 0) {
            has_uuid = true;
            break;
        }
    }

    // Identify user segments.
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        if (strcmp(bin->segments[i].name, "__TEXT") == 0) {
            has_text = true;
        }
    }

    // -----------------------------------------------------------------------
    // 4. Compute load command sizes
    // -----------------------------------------------------------------------

    uint32_t ncmds      = 0;
    uint32_t sizeofcmds = 0;

    // __PAGEZERO
    if (has_pagezero) {
        ncmds++;
        sizeofcmds += N00B_MACHO_SEG_CMD;
    }

    // User segments.
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        ncmds++;
        sizeofcmds += N00B_MACHO_SEG_CMD + bin->segments[i].nsects * N00B_MACHO_SECT_SIZE;
    }

    // __LINKEDIT
    if (has_linkedit) {
        ncmds++;
        sizeofcmds += N00B_MACHO_SEG_CMD;
    }

    // LC_SYMTAB
    if (has_symtab) {
        ncmds++;
        sizeofcmds += 24; // sizeof(n00b_macho_symtab_command_t)
    }

    // LC_DYSYMTAB
    if (has_dysymtab) {
        ncmds++;
        sizeofcmds += 80; // sizeof(n00b_macho_dysymtab_command_t)
    }

    // LC_DYLD_INFO_ONLY
    if (has_dyld_info) {
        ncmds++;
        sizeofcmds += 48; // sizeof(n00b_macho_dyld_info_command_t)
    }

    // LC_DYLD_CHAINED_FIXUPS (passthrough)
    if (has_chained) {
        ncmds++;
        sizeofcmds += 16; // linkedit_data_command: cmd(4) + cmdsize(4) + dataoff(4) + datasize(4)
    }

    // LC_LOAD_DYLINKER
    if (has_dylinker) {
        ncmds++;
        uint32_t cmdsize = 12 + (uint32_t)bin->dylinker->u8_bytes + 1;
        cmdsize = (uint32_t)pad_to_8(cmdsize);
        sizeofcmds += cmdsize;
    }

    // LC_UUID
    if (has_uuid) {
        ncmds++;
        sizeofcmds += 24; // sizeof(n00b_macho_uuid_command_t)
    }

    // LC_MAIN
    if (has_main) {
        ncmds++;
        sizeofcmds += 24; // sizeof(n00b_macho_entry_point_command_t)
    }

    // LC_LOAD_DYLIB
    for (uint32_t i = 0; i < bin->num_dylibs; i++) {
        ncmds++;
        uint32_t name_len = (bin->dylibs[i].name && bin->dylibs[i].name->data)
            ? (uint32_t)bin->dylibs[i].name->u8_bytes + 1
            : 1;
        uint32_t cmdsize = 24 + name_len;
        cmdsize = (uint32_t)pad_to_8(cmdsize);
        sizeofcmds += cmdsize;
    }

    // LC_FUNCTION_STARTS
    if (has_func_starts) {
        ncmds++;
        sizeofcmds += 16; // sizeof(n00b_macho_linkedit_data_command_t)
    }

    // LC_CODE_SIGNATURE
    if (has_code_sig) {
        ncmds++;
        sizeofcmds += 16;
    }

    // LC_SOURCE_VERSION
    if (has_src_ver) {
        ncmds++;
        sizeofcmds += 16; // sizeof(n00b_macho_source_version_command_t)
    }

    // LC_BUILD_VERSION
    if (has_build_ver) {
        ncmds++;
        sizeofcmds += 24 + 8 * bin->build_version->num_tools;
    }

    // LC_VERSION_MIN_*
    if (has_ver_min) {
        ncmds++;
        sizeofcmds += 16; // sizeof(n00b_macho_version_min_command_t)
    }

    // LC_RPATH (one per rpath)
    for (uint32_t i = 0; i < bin->num_rpaths; i++) {
        ncmds++;
        uint32_t path_len = (bin->rpaths[i] && bin->rpaths[i]->data)
            ? (uint32_t)bin->rpaths[i]->u8_bytes + 1
            : 1;
        uint32_t cmdsize = (uint32_t)pad_to_8(12 + path_len);
        sizeofcmds += cmdsize;
    }

    // LC_LINKER_OPTION
    for (uint32_t i = 0; i < bin->num_linker_options; i++) {
        ncmds++;
        // cmdsize = 12 (cmd + cmdsize + count) + sum of NUL-terminated strings
        uint32_t str_bytes = 0;

        for (uint32_t s = 0; s < bin->linker_options[i].count; s++) {
            str_bytes += (bin->linker_options[i].strings[s] && bin->linker_options[i].strings[s]->data)
                ? (uint32_t)bin->linker_options[i].strings[s]->u8_bytes + 1
                : 1;
        }

        sizeofcmds += (uint32_t)pad_to_8(12 + str_bytes);
    }

    // LC_DATA_IN_CODE
    if (has_data_in_code) {
        ncmds++;
        sizeofcmds += 16; // sizeof(n00b_macho_linkedit_data_command_t)
    }

    // LC_ENCRYPTION_INFO_64
    if (has_enc_info) {
        ncmds++;
        sizeofcmds += 24; // sizeof(n00b_macho_encryption_info_command64_t)
    }

    // LC_FILESET_ENTRY
    for (uint32_t i = 0; i < bin->num_fileset_entries; i++) {
        ncmds++;
        uint32_t id_len = (bin->fileset_entries[i].entry_id && bin->fileset_entries[i].entry_id->data)
            ? (uint32_t)bin->fileset_entries[i].entry_id->u8_bytes + 1
            : 1;
        uint32_t cmdsize = (uint32_t)pad_to_8(32 + id_len);
        sizeofcmds += cmdsize;
    }

    // -----------------------------------------------------------------------
    // 5. Compute file layout
    // -----------------------------------------------------------------------

    // __TEXT starts at 0, encompasses header + load commands + text sections.
    size_t text_start     = 0;
    size_t lc_end         = N00B_MACHO_HDR_SIZE + sizeofcmds;
    size_t data_pos       = align_up(lc_end, N00B_MACHO_PAGE_SIZE);

    // Assign section file offsets and compute segment sizes.
    // First, handle user segment section data.
    size_t cur_pos = data_pos;

    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_macho_segment_t *seg = &bin->segments[i];

        if (strcmp(seg->name, "__TEXT") == 0) {
            // __TEXT starts at 0, includes header + load commands.
            seg->fileoff  = 0;
            seg->vmaddr   = seg->vmaddr ? seg->vmaddr : 0x100000000ULL;

            // Place text sections after load commands.
            size_t sec_pos = lc_end;

            for (uint32_t j = 0; j < seg->nsects; j++) {
                n00b_macho_section_t *sec = &seg->sections[j];
                uint32_t sec_align = 1u << sec->align;
                sec_pos = align_up(sec_pos, sec_align);
                sec->offset = (uint32_t)sec_pos;
                sec->addr   = seg->vmaddr + sec_pos;

                size_t sec_size = sec->content
                    ? (size_t)n00b_buffer_len(sec->content) : sec->size;
                sec->size = sec_size;
                sec_pos += sec_size;
            }

            size_t text_end = align_up(sec_pos, N00B_MACHO_PAGE_SIZE);
            seg->filesize = text_end;
            seg->vmsize   = text_end;
            cur_pos       = text_end;
        }
        else {
            cur_pos       = align_up(cur_pos, N00B_MACHO_PAGE_SIZE);
            seg->fileoff  = cur_pos;

            if (seg->vmaddr == 0) {
                // Auto-assign vmaddr.
                seg->vmaddr = 0x100000000ULL + cur_pos;
            }

            size_t sec_pos = cur_pos;

            for (uint32_t j = 0; j < seg->nsects; j++) {
                n00b_macho_section_t *sec = &seg->sections[j];
                uint32_t sec_align = 1u << sec->align;
                sec_pos = align_up(sec_pos, sec_align);
                sec->offset = (uint32_t)sec_pos;
                sec->addr   = seg->vmaddr + (sec_pos - cur_pos);

                size_t sec_size = sec->content
                    ? (size_t)n00b_buffer_len(sec->content) : sec->size;
                sec->size = sec_size;
                sec_pos += sec_size;
            }

            size_t seg_data_size = sec_pos - cur_pos;
            seg->filesize = align_up(seg_data_size, N00B_MACHO_PAGE_SIZE);
            seg->vmsize   = seg->filesize;
            cur_pos      += seg->filesize;
        }
    }

    // If there's no __TEXT segment among user segments, the header + LC are
    // just bare at position 0.
    if (!has_text) {
        cur_pos = align_up(lc_end, N00B_MACHO_PAGE_SIZE);
    }

    // -----------------------------------------------------------------------
    // 6. Build __LINKEDIT content into a temporary writer
    // -----------------------------------------------------------------------

    n00b_writer_t *linkedit_w = n00b_writer_new(4096);

    size_t rebase_off_in_le  = 0, rebase_size  = 0;
    size_t bind_off_in_le    = 0, bind_size    = 0;
    size_t weak_bind_off_le  = 0, weak_bind_sz = 0;
    size_t lazy_bind_off_le  = 0, lazy_bind_sz = 0;
    size_t export_off_in_le  = 0, export_size  = 0;
    size_t chained_off_in_le = 0, chained_size  = 0;
    size_t func_start_off_le = 0, func_start_sz = 0;
    size_t dic_off_in_le     = 0, dic_size      = 0;
    size_t nlist_off_in_le   = 0;
    size_t indirect_off_le   = 0;
    size_t strtab_off_in_le  = 0;
    size_t codesig_off_le    = 0;

    // Get __TEXT vmaddr for function starts.
    uint64_t text_vmaddr = 0x100000000ULL;

    for (uint32_t i = 0; i < bin->num_segments; i++) {
        if (strcmp(bin->segments[i].name, "__TEXT") == 0) {
            text_vmaddr = bin->segments[i].vmaddr;
            break;
        }
    }

    // Rebase info.
    if (bin->num_rebases > 0) {
        rebase_off_in_le = n00b_writer_pos(linkedit_w);
        encode_rebase_opcodes(linkedit_w, bin);
        rebase_size = n00b_writer_pos(linkedit_w) - rebase_off_in_le;
        n00b_writer_align(linkedit_w, 8);
    }

    // Bind info (non-weak, non-lazy).
    if (bin->num_bindings > 0) {
        // Separate non-lazy, non-weak bindings.
        uint32_t normal_count = 0;
        uint32_t weak_count   = 0;
        uint32_t lazy_count   = 0;

        for (uint32_t i = 0; i < bin->num_bindings; i++) {
            if (bin->bindings[i].is_lazy) lazy_count++;
            else if (bin->bindings[i].is_weak) weak_count++;
            else normal_count++;
        }

        // Normal bindings.
        if (normal_count > 0) {
            bind_off_in_le = n00b_writer_pos(linkedit_w);
            n00b_macho_binding_t *normal_binds = n00b_alloc_array(
                n00b_macho_binding_t, normal_count);
            uint32_t ni = 0;

            for (uint32_t i = 0; i < bin->num_bindings; i++) {
                if (!bin->bindings[i].is_lazy && !bin->bindings[i].is_weak) {
                    normal_binds[ni++] = bin->bindings[i];
                }
            }

            encode_bind_opcodes(linkedit_w, bin, normal_binds, normal_count, false);
            bind_size = n00b_writer_pos(linkedit_w) - bind_off_in_le;
            n00b_writer_align(linkedit_w, 8);
        }

        // Weak bindings.
        if (weak_count > 0) {
            weak_bind_off_le = n00b_writer_pos(linkedit_w);
            n00b_macho_binding_t *weak_binds = n00b_alloc_array(
                n00b_macho_binding_t, weak_count);
            uint32_t wi = 0;

            for (uint32_t i = 0; i < bin->num_bindings; i++) {
                if (bin->bindings[i].is_weak) {
                    weak_binds[wi++] = bin->bindings[i];
                }
            }

            encode_bind_opcodes(linkedit_w, bin, weak_binds, weak_count, false);
            weak_bind_sz = n00b_writer_pos(linkedit_w) - weak_bind_off_le;
            n00b_writer_align(linkedit_w, 8);
        }

        // Lazy bindings.
        if (lazy_count > 0) {
            lazy_bind_off_le = n00b_writer_pos(linkedit_w);
            n00b_macho_binding_t *lazy_binds = n00b_alloc_array(
                n00b_macho_binding_t, lazy_count);
            uint32_t li = 0;

            for (uint32_t i = 0; i < bin->num_bindings; i++) {
                if (bin->bindings[i].is_lazy) {
                    lazy_binds[li++] = bin->bindings[i];
                }
            }

            encode_bind_opcodes(linkedit_w, bin, lazy_binds, lazy_count, true);
            lazy_bind_sz = n00b_writer_pos(linkedit_w) - lazy_bind_off_le;
            n00b_writer_align(linkedit_w, 8);
        }
    }

    // Chained fixups raw passthrough.
    if (has_chained) {
        chained_off_in_le = n00b_writer_pos(linkedit_w);
        n00b_buffer_t *raw = bin->chained_fixups->raw_data;
        chained_size = (size_t)n00b_buffer_len(raw);
        n00b_writer_write_bytes(linkedit_w, raw->data, chained_size);
        n00b_writer_align(linkedit_w, 8);
    }

    // Export trie.
    if (bin->num_exports > 0) {
        export_off_in_le = n00b_writer_pos(linkedit_w);
        export_size = encode_export_trie(linkedit_w, bin);
        n00b_writer_align(linkedit_w, 8);
    }

    // Function starts.
    if (has_func_starts) {
        func_start_off_le = n00b_writer_pos(linkedit_w);
        func_start_sz = encode_function_starts(linkedit_w, bin, text_vmaddr);
        n00b_writer_align(linkedit_w, 8);
    }

    // Data-in-code entries.
    if (has_data_in_code) {
        n00b_writer_align(linkedit_w, 4);
        dic_off_in_le = n00b_writer_pos(linkedit_w);

        for (uint32_t i = 0; i < bin->data_in_code->count; i++) {
            n00b_writer_write_u32(linkedit_w,
                bin->data_in_code->entries[i].offset);
            n00b_writer_write_u16(linkedit_w,
                bin->data_in_code->entries[i].length);
            n00b_writer_write_u16(linkedit_w,
                bin->data_in_code->entries[i].kind);
        }

        dic_size = n00b_writer_pos(linkedit_w) - dic_off_in_le;
        n00b_writer_align(linkedit_w, 8);
    }

    // Nlist array.
    nlist_off_in_le = n00b_writer_pos(linkedit_w);

    for (uint32_t i = 0; i < bin->num_symbols; i++) {
        n00b_writer_write_u32(linkedit_w, sym_name_offs ? sym_name_offs[i] : 0);
        n00b_writer_write_u8(linkedit_w, bin->symbols[i].type);
        n00b_writer_write_u8(linkedit_w, bin->symbols[i].sect);
        n00b_writer_write_u16(linkedit_w, bin->symbols[i].desc);
        n00b_writer_write_u64(linkedit_w, bin->symbols[i].value);
    }

    // Indirect symbols.
    if (bin->num_indirect_symbols > 0) {
        n00b_writer_align(linkedit_w, 4);
        indirect_off_le = n00b_writer_pos(linkedit_w);

        for (uint32_t i = 0; i < bin->num_indirect_symbols; i++) {
            n00b_writer_write_u32(linkedit_w, bin->indirect_symbols[i]);
        }
    }

    // String table.
    strtab_off_in_le = n00b_writer_pos(linkedit_w);
    n00b_strtab_builder_write(strtab, linkedit_w);

    // Code signature (pass-through).
    if (has_code_sig) {
        n00b_writer_align(linkedit_w, 16);
        codesig_off_le = n00b_writer_pos(linkedit_w);
        n00b_writer_write_buffer(linkedit_w, bin->code_signature->data);
    }

    size_t linkedit_size = n00b_writer_pos(linkedit_w);
    n00b_buffer_t *linkedit_buf = n00b_writer_finalize(linkedit_w);

    // -----------------------------------------------------------------------
    // 7. Place __LINKEDIT in the file
    // -----------------------------------------------------------------------

    size_t linkedit_fileoff = align_up(cur_pos, N00B_MACHO_PAGE_SIZE);
    size_t linkedit_vmaddr  = 0x100000000ULL + linkedit_fileoff;

    // Try to match vmaddr for __LINKEDIT relative to segments.
    if (bin->num_segments > 0) {
        n00b_macho_segment_t *last = &bin->segments[bin->num_segments - 1];
        linkedit_vmaddr = last->vmaddr + last->vmsize;
        linkedit_vmaddr = align_up(linkedit_vmaddr, N00B_MACHO_PAGE_SIZE);
    }

    size_t total_file_size = linkedit_fileoff
                           + align_up(linkedit_size, N00B_MACHO_PAGE_SIZE);

    // -----------------------------------------------------------------------
    // 8. Write the final output
    // -----------------------------------------------------------------------

    n00b_writer_t *w = n00b_writer_new(total_file_size + 64);

    // --- Mach-O header ---
    n00b_writer_write_u32(w, bin->header.magic);
    n00b_writer_write_u32(w, bin->header.cputype);
    n00b_writer_write_u32(w, bin->header.cpusubtype);
    n00b_writer_write_u32(w, bin->header.filetype);
    n00b_writer_write_u32(w, ncmds);
    n00b_writer_write_u32(w, sizeofcmds);
    n00b_writer_write_u32(w, bin->header.flags);
    n00b_writer_write_u32(w, bin->header.reserved);

    // --- Load commands ---

    // __PAGEZERO
    if (has_pagezero) {
        write_segment_command(w, "__PAGEZERO", 0,
                              0x100000000ULL, 0, 0, 0, 0, 0, 0);
    }

    // User segments.
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_macho_segment_t *seg = &bin->segments[i];

        write_segment_command(w, seg->name, seg->vmaddr, seg->vmsize,
                              seg->fileoff, seg->filesize,
                              seg->maxprot, seg->initprot,
                              seg->nsects, seg->flags);

        for (uint32_t j = 0; j < seg->nsects; j++) {
            write_section_header(w, &seg->sections[j]);
        }
    }

    // __LINKEDIT
    if (has_linkedit) {
        write_segment_command(w, "__LINKEDIT", linkedit_vmaddr,
                              align_up(linkedit_size, N00B_MACHO_PAGE_SIZE),
                              linkedit_fileoff,
                              align_up(linkedit_size, N00B_MACHO_PAGE_SIZE),
                              1, 1, 0, 0); // r-- prot
    }

    // LC_SYMTAB
    if (has_symtab) {
        n00b_writer_write_u32(w, LC_SYMTAB);
        n00b_writer_write_u32(w, 24);
        n00b_writer_write_u32(w, (uint32_t)(linkedit_fileoff + nlist_off_in_le));
        n00b_writer_write_u32(w, bin->num_symbols);
        n00b_writer_write_u32(w, (uint32_t)(linkedit_fileoff + strtab_off_in_le));
        n00b_writer_write_u32(w, (uint32_t)n00b_strtab_builder_size(strtab));
    }

    // LC_DYSYMTAB
    if (has_dysymtab) {
        n00b_writer_write_u32(w, LC_DYSYMTAB);
        n00b_writer_write_u32(w, 80);
        n00b_writer_write_u32(w, 0);        // ilocalsym
        n00b_writer_write_u32(w, nlocal);   // nlocalsym
        n00b_writer_write_u32(w, nlocal);   // iextdefsym
        n00b_writer_write_u32(w, nextdef);  // nextdefsym
        n00b_writer_write_u32(w, nlocal + nextdef); // iundefsym
        n00b_writer_write_u32(w, nundef);   // nundefsym
        n00b_writer_write_u32(w, 0);        // tocoff
        n00b_writer_write_u32(w, 0);        // ntoc
        n00b_writer_write_u32(w, 0);        // modtaboff
        n00b_writer_write_u32(w, 0);        // nmodtab
        n00b_writer_write_u32(w, 0);        // extrefsymoff
        n00b_writer_write_u32(w, 0);        // nextrefsyms

        if (bin->num_indirect_symbols > 0) {
            n00b_writer_write_u32(w,
                (uint32_t)(linkedit_fileoff + indirect_off_le));
            n00b_writer_write_u32(w, bin->num_indirect_symbols);
        }
        else {
            n00b_writer_write_u32(w, 0);
            n00b_writer_write_u32(w, 0);
        }

        n00b_writer_write_u32(w, 0);  // extreloff
        n00b_writer_write_u32(w, 0);  // nextrel
        n00b_writer_write_u32(w, 0);  // locreloff
        n00b_writer_write_u32(w, 0);  // nlocrel
    }

    // LC_DYLD_INFO_ONLY
    if (has_dyld_info) {
        n00b_writer_write_u32(w, LC_DYLD_INFO_ONLY);
        n00b_writer_write_u32(w, 48);
        n00b_writer_write_u32(w, rebase_size > 0
            ? (uint32_t)(linkedit_fileoff + rebase_off_in_le) : 0);
        n00b_writer_write_u32(w, (uint32_t)rebase_size);
        n00b_writer_write_u32(w, bind_size > 0
            ? (uint32_t)(linkedit_fileoff + bind_off_in_le) : 0);
        n00b_writer_write_u32(w, (uint32_t)bind_size);
        n00b_writer_write_u32(w, weak_bind_sz > 0
            ? (uint32_t)(linkedit_fileoff + weak_bind_off_le) : 0);
        n00b_writer_write_u32(w, (uint32_t)weak_bind_sz);
        n00b_writer_write_u32(w, lazy_bind_sz > 0
            ? (uint32_t)(linkedit_fileoff + lazy_bind_off_le) : 0);
        n00b_writer_write_u32(w, (uint32_t)lazy_bind_sz);
        n00b_writer_write_u32(w, export_size > 0
            ? (uint32_t)(linkedit_fileoff + export_off_in_le) : 0);
        n00b_writer_write_u32(w, (uint32_t)export_size);
    }

    // LC_DYLD_CHAINED_FIXUPS (passthrough)
    if (has_chained) {
        n00b_writer_write_u32(w, LC_DYLD_CHAINED_FIXUPS);
        n00b_writer_write_u32(w, 16);
        n00b_writer_write_u32(w, (uint32_t)(linkedit_fileoff + chained_off_in_le));
        n00b_writer_write_u32(w, (uint32_t)chained_size);
    }

    // LC_LOAD_DYLINKER
    if (has_dylinker) {
        uint32_t name_len = (uint32_t)bin->dylinker->u8_bytes + 1;
        uint32_t cmdsize  = (uint32_t)pad_to_8(12 + name_len);
        n00b_writer_write_u32(w, LC_LOAD_DYLINKER);
        n00b_writer_write_u32(w, cmdsize);
        n00b_writer_write_u32(w, 12); // name_offset
        n00b_writer_write_bytes(w, bin->dylinker->data,
                                 bin->dylinker->u8_bytes);
        n00b_writer_write_u8(w, 0);

        // Pad to cmdsize.
        size_t written = 12 + name_len;
        if (written < cmdsize) {
            n00b_writer_write_zeros(w, cmdsize - written);
        }
    }

    // LC_UUID
    if (has_uuid) {
        n00b_writer_write_u32(w, LC_UUID);
        n00b_writer_write_u32(w, 24);
        n00b_writer_write_bytes(w, bin->uuid, 16);
    }

    // LC_MAIN
    if (has_main) {
        n00b_writer_write_u32(w, LC_MAIN);
        n00b_writer_write_u32(w, 24);
        n00b_writer_write_u64(w, bin->entrypoint);
        n00b_writer_write_u64(w, bin->stack_size);
    }

    // LC_LOAD_DYLIB
    for (uint32_t i = 0; i < bin->num_dylibs; i++) {
        n00b_macho_dylib_t *dl = &bin->dylibs[i];
        uint32_t name_len = (dl->name && dl->name->data)
            ? (uint32_t)dl->name->u8_bytes + 1 : 1;
        uint32_t cmdsize = (uint32_t)pad_to_8(24 + name_len);

        n00b_writer_write_u32(w, dl->cmd ? dl->cmd : LC_LOAD_DYLIB);
        n00b_writer_write_u32(w, cmdsize);
        n00b_writer_write_u32(w, 24); // name_offset
        n00b_writer_write_u32(w, dl->timestamp);
        n00b_writer_write_u32(w, dl->current_version);
        n00b_writer_write_u32(w, dl->compat_version);

        if (dl->name && dl->name->data) {
            n00b_writer_write_bytes(w, dl->name->data, dl->name->u8_bytes);
        }

        n00b_writer_write_u8(w, 0);

        size_t written = 24 + name_len;

        if (written < cmdsize) {
            n00b_writer_write_zeros(w, cmdsize - written);
        }
    }

    // LC_FUNCTION_STARTS
    if (has_func_starts) {
        n00b_writer_write_u32(w, LC_FUNCTION_STARTS);
        n00b_writer_write_u32(w, 16);
        n00b_writer_write_u32(w,
            (uint32_t)(linkedit_fileoff + func_start_off_le));
        n00b_writer_write_u32(w, (uint32_t)func_start_sz);
    }

    // LC_CODE_SIGNATURE
    if (has_code_sig) {
        n00b_writer_write_u32(w, LC_CODE_SIGNATURE);
        n00b_writer_write_u32(w, 16);
        n00b_writer_write_u32(w,
            (uint32_t)(linkedit_fileoff + codesig_off_le));
        n00b_writer_write_u32(w,
            (uint32_t)n00b_buffer_len(bin->code_signature->data));
    }

    // LC_SOURCE_VERSION
    if (has_src_ver) {
        n00b_writer_write_u32(w, LC_SOURCE_VERSION);
        n00b_writer_write_u32(w, 16);
        n00b_writer_write_u64(w, bin->source_version);
    }

    // LC_BUILD_VERSION
    if (has_build_ver) {
        uint32_t bv_cmdsize = 24 + 8 * bin->build_version->num_tools;
        n00b_writer_write_u32(w, LC_BUILD_VERSION);
        n00b_writer_write_u32(w, bv_cmdsize);
        n00b_writer_write_u32(w, bin->build_version->platform);
        n00b_writer_write_u32(w, bin->build_version->minos);
        n00b_writer_write_u32(w, bin->build_version->sdk);
        n00b_writer_write_u32(w, bin->build_version->num_tools);

        for (uint32_t i = 0; i < bin->build_version->num_tools; i++) {
            n00b_writer_write_u32(w, bin->build_version->tools[i].tool);
            n00b_writer_write_u32(w, bin->build_version->tools[i].version);
        }
    }

    // LC_VERSION_MIN_*
    if (has_ver_min) {
        n00b_writer_write_u32(w, bin->version_min->cmd);
        n00b_writer_write_u32(w, 16);
        n00b_writer_write_u32(w, bin->version_min->version);
        n00b_writer_write_u32(w, bin->version_min->sdk);
    }

    // LC_RPATH
    for (uint32_t i = 0; i < bin->num_rpaths; i++) {
        uint32_t path_len = (bin->rpaths[i] && bin->rpaths[i]->data)
            ? (uint32_t)bin->rpaths[i]->u8_bytes + 1
            : 1;
        uint32_t cmdsize = (uint32_t)pad_to_8(12 + path_len);
        n00b_writer_write_u32(w, LC_RPATH);
        n00b_writer_write_u32(w, cmdsize);
        n00b_writer_write_u32(w, 12); // path_offset

        if (bin->rpaths[i] && bin->rpaths[i]->data) {
            n00b_writer_write_bytes(w, bin->rpaths[i]->data,
                                     bin->rpaths[i]->u8_bytes);
        }

        n00b_writer_write_u8(w, 0);

        size_t written = 12 + path_len;

        if (written < cmdsize) {
            n00b_writer_write_zeros(w, cmdsize - written);
        }
    }

    // LC_LINKER_OPTION
    for (uint32_t i = 0; i < bin->num_linker_options; i++) {
        uint32_t str_bytes = 0;

        for (uint32_t s = 0; s < bin->linker_options[i].count; s++) {
            str_bytes += (bin->linker_options[i].strings[s] && bin->linker_options[i].strings[s]->data)
                ? (uint32_t)bin->linker_options[i].strings[s]->u8_bytes + 1
                : 1;
        }

        uint32_t cmdsize = (uint32_t)pad_to_8(12 + str_bytes);
        n00b_writer_write_u32(w, LC_LINKER_OPTION);
        n00b_writer_write_u32(w, cmdsize);
        n00b_writer_write_u32(w, bin->linker_options[i].count);

        for (uint32_t s = 0; s < bin->linker_options[i].count; s++) {
            if (bin->linker_options[i].strings[s] && bin->linker_options[i].strings[s]->data) {
                n00b_writer_write_bytes(
                    w, bin->linker_options[i].strings[s]->data,
                    bin->linker_options[i].strings[s]->u8_bytes);
            }

            n00b_writer_write_u8(w, 0);
        }

        size_t written = 12 + str_bytes;

        if (written < cmdsize) {
            n00b_writer_write_zeros(w, cmdsize - written);
        }
    }

    // LC_DATA_IN_CODE
    if (has_data_in_code) {
        n00b_writer_write_u32(w, LC_DATA_IN_CODE);
        n00b_writer_write_u32(w, 16);
        n00b_writer_write_u32(w,
            (uint32_t)(linkedit_fileoff + dic_off_in_le));
        n00b_writer_write_u32(w, (uint32_t)dic_size);
    }

    // LC_ENCRYPTION_INFO_64
    if (has_enc_info) {
        n00b_writer_write_u32(w, LC_ENCRYPTION_INFO_64);
        n00b_writer_write_u32(w, 24);
        n00b_writer_write_u32(w, bin->encryption_info->cryptoff);
        n00b_writer_write_u32(w, bin->encryption_info->cryptsize);
        n00b_writer_write_u32(w, bin->encryption_info->cryptid);
        n00b_writer_write_u32(w, 0); // pad
    }

    // LC_FILESET_ENTRY
    for (uint32_t i = 0; i < bin->num_fileset_entries; i++) {
        uint32_t id_len = (bin->fileset_entries[i].entry_id && bin->fileset_entries[i].entry_id->data)
            ? (uint32_t)bin->fileset_entries[i].entry_id->u8_bytes + 1
            : 1;
        uint32_t cmdsize = (uint32_t)pad_to_8(32 + id_len);
        n00b_writer_write_u32(w, LC_FILESET_ENTRY);
        n00b_writer_write_u32(w, cmdsize);
        n00b_writer_write_u64(w, bin->fileset_entries[i].vmaddr);
        n00b_writer_write_u64(w, bin->fileset_entries[i].fileoff);
        n00b_writer_write_u32(w, 32); // entry_id offset
        n00b_writer_write_u32(w, bin->fileset_entries[i].reserved);

        if (bin->fileset_entries[i].entry_id && bin->fileset_entries[i].entry_id->data) {
            n00b_writer_write_bytes(
                w, bin->fileset_entries[i].entry_id->data,
                bin->fileset_entries[i].entry_id->u8_bytes);
        }

        n00b_writer_write_u8(w, 0);

        size_t written = 32 + id_len;

        if (written < cmdsize) {
            n00b_writer_write_zeros(w, cmdsize - written);
        }
    }

    // --- Section content ---
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        for (uint32_t j = 0; j < bin->segments[i].nsects; j++) {
            n00b_macho_section_t *sec = &bin->segments[i].sections[j];

            if (sec->content && n00b_buffer_len(sec->content) > 0) {
                n00b_writer_setpos(w, sec->offset);
                n00b_writer_write_buffer(w, sec->content);
            }
        }
    }

    // --- __LINKEDIT content ---
    n00b_writer_setpos(w, linkedit_fileoff);
    n00b_writer_write_bytes(w, linkedit_buf->data,
                             n00b_buffer_len(linkedit_buf));

    // Pad to total_file_size.
    if (n00b_writer_pos(w) < total_file_size) {
        n00b_writer_write_zeros(w, total_file_size - n00b_writer_pos(w));
    }

    n00b_writer_setpos(w, total_file_size);
    n00b_buffer_t *result = n00b_writer_finalize(w);

    return n00b_result_ok(n00b_buffer_t *, result);

    (void)text_start;
}

// ============================================================================
// Fat binary builder
// ============================================================================

static inline uint32_t
swap32_be(uint32_t v)
{
    // Swap to big-endian on little-endian host.
    union [[n00b::raw_union]] {
        uint16_t u;
        uint8_t  b[2];
    } probe = {.u = 1};

    if (probe.b[0] == 1) {
        // Host is little-endian, swap.
        return ((v >> 24) & 0xFF)
             | ((v >>  8) & 0xFF00)
             | ((v <<  8) & 0xFF0000)
             | ((v << 24) & 0xFF000000);
    }

    return v;
}

// Shared re-fat serialization seam (NFR-11). Extracted from the historical
// n00b_macho_build_fat body so that both build_fat (every slice align == 14)
// and n00b_macho_refat (per-slice alignment) reuse one serializer. Declared in
// macho_fat_rewrite_internal.h (it stays an internal seam — the §8 public
// surface is frozen). The cursor/field arithmetic is now checked: a slice whose
// 2^align-padded offset or size exceeds the fat_arch u32 field, or a running
// cursor that overflows, yields Err(...) instead of the old silent (uint32_t)
// truncation. For valid inputs (slices well under 4 GiB, the only case build_fat
// ever produced) the emitted bytes are identical to the pre-refactor builder:
// same big-endian header, same arch table, same 16K-aligned placement.
n00b_result_t(n00b_buffer_t *)
_n00b_macho_refat_serialize(n00b_buffer_t   **thin_bufs,
                            uint32_t         *cputypes,
                            uint32_t         *cpusubtypes,
                            uint32_t         *aligns,
                            uint32_t          count,
                            n00b_allocator_t *allocator)
{
    // Fat header + fat_arch[] (8-byte header + 20 bytes per arch). The first
    // slice lands at the first 16K page boundary past the header (matching the
    // historical builder's N00B_MACHO_PAGE_SIZE header alignment).
    size_t fat_hdr_size = 8 + (size_t)count * 20;
    size_t pos          = align_up(fat_hdr_size, N00B_MACHO_PAGE_SIZE);

    uint32_t *slice_offsets = n00b_alloc_array(uint32_t, count,
                                               .allocator = allocator);
    uint32_t *slice_sizes   = n00b_alloc_array(uint32_t, count,
                                               .allocator = allocator);

    for (uint32_t i = 0; i < count; i++) {
        // Align the cursor to this slice's 2^align boundary. (build_fat passes
        // align == 14 for every slice, reproducing the old 16K placement.)
        size_t slice_align = (size_t)1 << aligns[i];
        size_t aligned     = align_up(pos, slice_align);

        // Cursor alignment must not overflow the addressable cursor. This (and
        // the post-slice `advanced < pos` guard below) is a defensive u64
        // cursor-wrap check: the per-slice u32 caps (`pos > UINT32_MAX` and
        // `slice_len > UINT32_MAX`, below) fire first, holding every slice under
        // 4 GiB, so the 64-bit cursor cannot wrap without ~2^64 bytes of input.
        // It is therefore unreachable for real `n00b_buffer_t` inputs and is
        // intentionally not unit-tested (an exabyte-allocating test is infeasible).
        if (aligned < pos) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_FAT_ERR_ALIGN_OVERFLOW);
        }
        pos = aligned;

        // The fat_arch.offset field is u32: the slice must start below 4 GiB.
        if (pos > (size_t)UINT32_MAX) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_FAT_ERR_SLICE_TOO_LARGE);
        }

        size_t slice_len = (size_t)n00b_buffer_len(thin_bufs[i]);

        // The fat_arch.size field is u32: the slice must fit below 4 GiB.
        if (slice_len > (size_t)UINT32_MAX) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_FAT_ERR_SLICE_TOO_LARGE);
        }

        slice_offsets[i] = (uint32_t)pos;
        slice_sizes[i]   = (uint32_t)slice_len;

        // Advance the cursor past this slice, guarding the running total.
        size_t advanced = pos + slice_len;
        if (advanced < pos) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_FAT_ERR_ALIGN_OVERFLOW);
        }
        pos = advanced;
    }

    // Write fat binary. The writer's backing buffer (and every growth, and the
    // finalized output) is allocated from the caller's allocator, so the result
    // is arena-owned directly with no re-home copy (DF-007-01 / NFR-05). When
    // allocator == nullptr (the n00b_macho_build_fat path) this is the runtime
    // default, preserving build_fat's byte-identical, copy-free behavior.
    n00b_writer_t *w = n00b_writer_new(pos + 64, .allocator = allocator);

    // Fat header (big-endian).
    n00b_writer_write_u32(w, swap32_be(FAT_MAGIC));
    n00b_writer_write_u32(w, swap32_be(count));

    // Fat arch entries (big-endian).
    for (uint32_t i = 0; i < count; i++) {
        n00b_writer_write_u32(w, swap32_be(cputypes[i]));
        n00b_writer_write_u32(w, swap32_be(cpusubtypes[i]));
        n00b_writer_write_u32(w, swap32_be(slice_offsets[i]));
        n00b_writer_write_u32(w, swap32_be(slice_sizes[i]));
        n00b_writer_write_u32(w, swap32_be(aligns[i]));
    }

    // Write each thin binary at its offset.
    for (uint32_t i = 0; i < count; i++) {
        n00b_writer_setpos(w, slice_offsets[i]);
        n00b_writer_write_buffer(w, thin_bufs[i]);
    }

    n00b_writer_setpos(w, pos);

    if (n00b_writer_has_error(w)) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_FAT_ERR_REFAT);
    }

    // NFR-04/NFR-05: the writer was constructed with the caller's allocator, so
    // its finalized buffer is already owned by that allocator (DF-007-01: no
    // re-home copy). When allocator == nullptr the buffer is runtime-default
    // owned, so n00b_macho_build_fat stays byte-identical and copy-free.
    n00b_buffer_t *result = n00b_writer_finalize(w);

    return n00b_result_ok(n00b_buffer_t *, result);
}

n00b_result_t(n00b_buffer_t *)
n00b_macho_build_fat(n00b_macho_fat_t *fat)
{
    if (!fat || fat->count == 0) {
        return n00b_result_err(n00b_buffer_t *, N00B_ERR_BUILD);
    }

    // Build each thin binary, collecting the per-slice identity the serializer
    // needs. build_fat keeps its historical contract: every slice uses
    // align == 14 (16K), and cputype/cpusubtype come from each binary header.
    n00b_buffer_t **thin_bufs    = n00b_alloc_array(n00b_buffer_t *, fat->count);
    uint32_t       *cputypes     = n00b_alloc_array(uint32_t, fat->count);
    uint32_t       *cpusubtypes  = n00b_alloc_array(uint32_t, fat->count);
    uint32_t       *aligns       = n00b_alloc_array(uint32_t, fat->count);

    for (uint32_t i = 0; i < fat->count; i++) {
        auto r = n00b_macho_build(fat->binaries[i]);

        if (n00b_result_is_err(r)) {
            return r;
        }

        thin_bufs[i]   = n00b_result_get(r);
        cputypes[i]    = fat->binaries[i]->header.cputype;
        cpusubtypes[i] = fat->binaries[i]->header.cpusubtype;
        aligns[i]      = 14; // 2^14 == 16384, preserving the historical layout.
    }

    // build_fat preserves its historical default: the serializer's scratch
    // arrays come from the default allocator, keeping output byte-identical.
    auto sr = _n00b_macho_refat_serialize(thin_bufs,
                                          cputypes,
                                          cpusubtypes,
                                          aligns,
                                          fat->count,
                                          nullptr);

    if (n00b_result_is_err(sr)) {
        // The serializer's overflow guards are the only new failure path; map
        // them back to the builder's historical N00B_ERR_BUILD verdict so the
        // build_fat contract (callers expect N00B_ERR_BUILD) is unchanged.
        return n00b_result_err(n00b_buffer_t *, N00B_ERR_BUILD);
    }

    return n00b_result_ok(n00b_buffer_t *, n00b_result_get(sr));
}

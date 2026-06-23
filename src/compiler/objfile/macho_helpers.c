#include <string.h>

#include "compiler/objfile/macho_build.h"

// ============================================================================
// Binary creation
// ============================================================================

n00b_macho_binary_t *
n00b_macho_binary_new(uint32_t cputype, uint32_t cpusubtype, uint32_t filetype)
{
    n00b_macho_binary_t *bin = n00b_alloc(n00b_macho_binary_t);

    memset(bin, 0, sizeof(*bin));

    bin->header.magic      = MH_MAGIC_64;
    bin->header.cputype    = cputype;
    bin->header.cpusubtype = cpusubtype;
    bin->header.filetype   = filetype;

    return bin;
}

// ============================================================================
// Array growth helper
// ============================================================================

// Only reallocate when count is 0 or a power of 2 (i.e. at capacity
// boundary).  Allocations double each time, giving amortized O(1) growth.
#define GROW_ARRAY(ptr, count, elem_type)                      \
    do {                                                       \
        uint32_t old_count = *(count);                         \
        uint32_t new_count = old_count + 1;                    \
        bool need_alloc = (old_count == 0)                     \
                       || (old_count & (old_count - 1)) == 0;  \
        if (need_alloc) {                                      \
            uint32_t cap = old_count == 0 ? 4 : old_count * 2; \
            elem_type *new_arr = n00b_alloc_array(             \
                elem_type, cap);                               \
            if (old_count > 0) {                               \
                memcpy(new_arr, *(ptr),                        \
                       old_count * sizeof(elem_type));          \
            }                                                  \
            *(ptr) = new_arr;                                  \
        }                                                      \
        *(count) = new_count;                                  \
    } while (0)

// ============================================================================
// Segment management
// ============================================================================

n00b_macho_segment_t *
n00b_macho_add_segment(n00b_macho_binary_t *bin, const char *name,
                       uint32_t initprot, uint32_t maxprot)
{
    GROW_ARRAY(&bin->segments, &bin->num_segments, n00b_macho_segment_t);

    n00b_macho_segment_t *seg = &bin->segments[bin->num_segments - 1];
    memset(seg, 0, sizeof(*seg));

    if (name) {
        strncpy(seg->name, name, 16);
        seg->name[16] = '\0';
    }

    seg->initprot = initprot;
    seg->maxprot  = maxprot;

    return seg;
}

// ============================================================================
// Section management
// ============================================================================

n00b_macho_section_t *
n00b_macho_add_section(n00b_macho_segment_t *seg, const char *sectname,
                       const char *segname, uint32_t flags, uint32_t align)
{
    uint32_t old_count = seg->nsects;
    uint32_t new_count = old_count + 1;

    n00b_macho_section_t *new_arr = n00b_alloc_array(n00b_macho_section_t,
                                                      new_count);

    if (old_count > 0) {
        memcpy(new_arr, seg->sections,
               old_count * sizeof(n00b_macho_section_t));
    }

    seg->sections = new_arr;
    seg->nsects   = new_count;

    n00b_macho_section_t *sec = &new_arr[new_count - 1];
    memset(sec, 0, sizeof(*sec));

    if (sectname) {
        strncpy(sec->sectname, sectname, 16);
        sec->sectname[16] = '\0';
    }

    if (segname) {
        strncpy(sec->segname, segname, 16);
        sec->segname[16] = '\0';
    }

    sec->flags = flags;
    sec->align = align;

    return sec;
}

// ============================================================================
// Symbol management
// ============================================================================

n00b_macho_symbol_t *
n00b_macho_add_symbol(n00b_macho_binary_t *bin, const char *name,
                      uint8_t type, uint8_t sect, uint16_t desc,
                      uint64_t value)
{
    // Materialize any lazily-captured symbol table before appending, so a parsed
    // binary's existing symbols aren't lost; then symbols[] is fully owned here.
    n00b_macho_ensure_symbols(bin);
    bin->symbols_parsed = true;

    GROW_ARRAY(&bin->symbols, &bin->num_symbols, n00b_macho_symbol_t);

    n00b_macho_symbol_t *sym = &bin->symbols[bin->num_symbols - 1];
    memset(sym, 0, sizeof(*sym));

    if (name) {
        sym->name = n00b_string_from_cstr(name);
    }

    sym->type  = type;
    sym->sect  = sect;
    sym->desc  = desc;
    sym->value = value;

    return sym;
}

// ============================================================================
// Dylib management
// ============================================================================

n00b_macho_dylib_t *
n00b_macho_add_dylib(n00b_macho_binary_t *bin, const char *path,
                     uint32_t current_version, uint32_t compat_version)
{
    GROW_ARRAY(&bin->dylibs, &bin->num_dylibs, n00b_macho_dylib_t);

    n00b_macho_dylib_t *dl = &bin->dylibs[bin->num_dylibs - 1];
    memset(dl, 0, sizeof(*dl));

    if (path) {
        dl->name = n00b_string_from_cstr(path);
    }

    dl->current_version = current_version;
    dl->compat_version  = compat_version;
    dl->cmd             = LC_LOAD_DYLIB;

    return dl;
}

// ============================================================================
// Binding info
// ============================================================================

n00b_macho_binding_t *
n00b_macho_add_binding(n00b_macho_binary_t *bin, const char *symbol_name,
                       int32_t library_ordinal, uint8_t segment_index,
                       uint64_t address, uint8_t type, int64_t addend)
{
    GROW_ARRAY(&bin->bindings, &bin->num_bindings, n00b_macho_binding_t);

    n00b_macho_binding_t *b = &bin->bindings[bin->num_bindings - 1];
    memset(b, 0, sizeof(*b));

    if (symbol_name) {
        b->symbol_name = n00b_string_from_cstr(symbol_name);
    }

    b->library_ordinal = library_ordinal;
    b->segment_index   = segment_index;
    b->address         = address;
    b->type            = type;
    b->addend          = addend;

    return b;
}

// ============================================================================
// Rebase info
// ============================================================================

n00b_macho_rebase_t *
n00b_macho_add_rebase(n00b_macho_binary_t *bin, uint8_t segment_index,
                      uint64_t address, uint8_t type)
{
    GROW_ARRAY(&bin->rebases, &bin->num_rebases, n00b_macho_rebase_t);

    n00b_macho_rebase_t *r = &bin->rebases[bin->num_rebases - 1];
    memset(r, 0, sizeof(*r));

    r->segment_index = segment_index;
    r->address       = address;
    r->type          = type;

    return r;
}

// ============================================================================
// Export info
// ============================================================================

n00b_macho_export_t *
n00b_macho_add_export(n00b_macho_binary_t *bin, const char *name,
                      uint64_t address, uint64_t flags)
{
    // Materialize any lazily-captured export trie before appending, so a parsed
    // binary's existing exports aren't lost; then exports[] is fully owned here.
    n00b_macho_ensure_exports(bin);
    bin->exports_parsed = true;

    GROW_ARRAY(&bin->exports, &bin->num_exports, n00b_macho_export_t);

    n00b_macho_export_t *e = &bin->exports[bin->num_exports - 1];
    memset(e, 0, sizeof(*e));

    if (name) {
        e->name = n00b_string_from_cstr(name);
    }

    e->address = address;
    e->flags   = flags;

    return e;
}

// ============================================================================
// Convenience setters
// ============================================================================

void
n00b_macho_set_entry(n00b_macho_binary_t *bin, uint64_t entryoff,
                     uint64_t stacksize)
{
    bin->entrypoint = entryoff;
    bin->stack_size = stacksize;
}

void
n00b_macho_set_dylinker(n00b_macho_binary_t *bin, const char *path)
{
    if (path) {
        bin->dylinker = n00b_string_from_cstr(path);
    }
}

void
n00b_macho_set_uuid(n00b_macho_binary_t *bin, const uint8_t uuid[16])
{
    memcpy(bin->uuid, uuid, 16);
}

void
n00b_macho_set_function_starts(n00b_macho_binary_t *bin,
                               uint64_t *addresses, uint32_t count)
{
    if (!bin->function_starts) {
        bin->function_starts = n00b_alloc(n00b_macho_function_starts_t);
    }

    uint64_t *new_addrs = n00b_alloc_array(uint64_t, count);
    memcpy(new_addrs, addresses, count * sizeof(uint64_t));

    bin->function_starts->addresses = new_addrs;
    bin->function_starts->count     = count;
}

void
n00b_macho_set_source_version(n00b_macho_binary_t *bin, uint64_t version)
{
    bin->source_version = version;
}

void
n00b_macho_set_build_version(n00b_macho_binary_t *bin,
                              uint32_t platform, uint32_t minos, uint32_t sdk,
                              n00b_macho_build_tool_t *tools,
                              uint32_t num_tools)
{
    if (!bin->build_version) {
        bin->build_version = n00b_alloc(n00b_macho_build_version_t);
    }

    bin->build_version->platform  = platform;
    bin->build_version->minos     = minos;
    bin->build_version->sdk       = sdk;
    bin->build_version->num_tools = num_tools;

    if (num_tools > 0 && tools) {
        bin->build_version->tools = n00b_alloc_array(
            n00b_macho_build_tool_t, num_tools);
        memcpy(bin->build_version->tools, tools,
               num_tools * sizeof(n00b_macho_build_tool_t));
    }
    else {
        bin->build_version->tools = nullptr;
    }
}

void
n00b_macho_add_rpath(n00b_macho_binary_t *bin, const char *path)
{
    uint32_t old_count = bin->num_rpaths;
    uint32_t new_count = old_count + 1;
    n00b_string_t **new_arr = n00b_alloc_array(n00b_string_t *, new_count);

    if (old_count > 0) {
        memcpy(new_arr, bin->rpaths, old_count * sizeof(n00b_string_t *));
    }

    if (path) {
        new_arr[old_count] = n00b_string_from_cstr(path);
    }

    bin->rpaths     = new_arr;
    bin->num_rpaths = new_count;
}

void
n00b_macho_set_version_min(n00b_macho_binary_t *bin,
                            uint32_t cmd, uint32_t version, uint32_t sdk)
{
    if (!bin->version_min) {
        bin->version_min = n00b_alloc(n00b_macho_version_min_t);
    }

    bin->version_min->cmd     = cmd;
    bin->version_min->version = version;
    bin->version_min->sdk     = sdk;
}

void
n00b_macho_add_linker_option(n00b_macho_binary_t *bin,
                              const char **strings, uint32_t count)
{
    uint32_t old_count = bin->num_linker_options;
    uint32_t new_count = old_count + 1;
    n00b_macho_linker_option_t *new_arr = n00b_alloc_array(
        n00b_macho_linker_option_t, new_count);

    if (old_count > 0) {
        memcpy(new_arr, bin->linker_options,
               old_count * sizeof(n00b_macho_linker_option_t));
    }

    new_arr[old_count].count = count;

    if (count > 0 && strings) {
        new_arr[old_count].strings = n00b_alloc_array(n00b_string_t *, count);

        for (uint32_t i = 0; i < count; i++) {
            if (strings[i]) {
                new_arr[old_count].strings[i] = n00b_string_from_cstr(
                    strings[i]);
            }
        }
    }

    bin->linker_options     = new_arr;
    bin->num_linker_options = new_count;
}

void
n00b_macho_set_data_in_code(n00b_macho_binary_t *bin,
                             n00b_macho_data_in_code_entry_t *entries,
                             uint32_t count)
{
    if (!bin->data_in_code) {
        bin->data_in_code = n00b_alloc(n00b_macho_data_in_code_t);
    }

    if (count > 0 && entries) {
        bin->data_in_code->entries = n00b_alloc_array(
            n00b_macho_data_in_code_entry_t, count);
        memcpy(bin->data_in_code->entries, entries,
               count * sizeof(n00b_macho_data_in_code_entry_t));
    }

    bin->data_in_code->count = count;
}

void
n00b_macho_set_encryption_info(n00b_macho_binary_t *bin,
                                uint32_t cryptoff, uint32_t cryptsize,
                                uint32_t cryptid)
{
    if (!bin->encryption_info) {
        bin->encryption_info = n00b_alloc(n00b_macho_encryption_info_t);
    }

    bin->encryption_info->cryptoff  = cryptoff;
    bin->encryption_info->cryptsize = cryptsize;
    bin->encryption_info->cryptid   = cryptid;
}

void
n00b_macho_add_fileset_entry(n00b_macho_binary_t *bin,
                              uint64_t vmaddr, uint64_t fileoff,
                              const char *entry_id)
{
    uint32_t old_count = bin->num_fileset_entries;
    uint32_t new_count = old_count + 1;
    n00b_macho_fileset_entry_t *new_arr = n00b_alloc_array(
        n00b_macho_fileset_entry_t, new_count);

    if (old_count > 0) {
        memcpy(new_arr, bin->fileset_entries,
               old_count * sizeof(n00b_macho_fileset_entry_t));
    }

    new_arr[old_count].vmaddr  = vmaddr;
    new_arr[old_count].fileoff = fileoff;

    if (entry_id) {
        new_arr[old_count].entry_id = n00b_string_from_cstr(entry_id);
    }

    bin->fileset_entries     = new_arr;
    bin->num_fileset_entries = new_count;
}

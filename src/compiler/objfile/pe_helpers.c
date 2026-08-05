#include <string.h>
#ifndef _WIN32
#include <strings.h>  // strcasecmp
#endif
#include "compiler/objfile/pe_build.h"

// ============================================================================
// GROW_ARRAY helper
// ============================================================================

#define GROW_ARRAY(arr, count, type) do {                        \
    if (((count) & ((count) - 1)) == 0) {                       \
        uint32_t cap = (count) == 0 ? 1 : (count) * 2;          \
        type *tmp = n00b_alloc_array(type, cap);                 \
        if ((count) > 0)                                         \
            memcpy(tmp, (arr), (count) * sizeof(type));          \
        (arr) = tmp;                                              \
    }                                                             \
} while (0)

// ============================================================================
// Binary creation
// ============================================================================

n00b_pe_binary_t *
n00b_pe_binary_new(uint16_t machine, uint16_t subsystem)
{
    n00b_pe_binary_t *bin = n00b_alloc(n00b_pe_binary_t);

    bin->magic             = N00B_PE_OPT_MAGIC_PE32P;
    bin->machine           = machine;
    bin->subsystem         = subsystem;
    bin->characteristics   = N00B_PE_CHAR_EXECUTABLE_IMAGE | N00B_PE_CHAR_LARGE_ADDRESS;
    bin->pe_offset         = 0x80;  // Standard offset
    bin->section_alignment = 0x1000;
    bin->file_alignment    = 0x200;
    bin->imagebase         = 0x0000000140000000ULL;
    bin->major_os_version  = 6;
    bin->minor_os_version  = 0;
    bin->dll_characteristics = N00B_PE_DLLCHAR_DYNAMIC_BASE
                              | N00B_PE_DLLCHAR_NX_COMPAT
                              | N00B_PE_DLLCHAR_HIGH_ENTROPY_VA;
    bin->num_data_dirs     = N00B_PE_NUM_DATA_DIRS;

    // DOS header defaults
    bin->dos_header.e_magic  = N00B_PE_MAGIC_MZ;
    bin->dos_header.e_lfanew = 0x80;

    return bin;
}

// ============================================================================
// Section management
// ============================================================================

n00b_pe_section_t *
n00b_pe_add_section(n00b_pe_binary_t *bin, const char *name,
                    uint32_t characteristics)
{
    GROW_ARRAY(bin->sections, bin->num_sections, n00b_pe_section_t);

    n00b_pe_section_t *s = &bin->sections[bin->num_sections++];

    s->name            = n00b_string_from_cstr(name);
    s->characteristics = characteristics;

    return s;
}

// ============================================================================
// Import management
// ============================================================================

n00b_pe_import_t *
n00b_pe_add_import(n00b_pe_binary_t *bin, const char *dll_name)
{
    GROW_ARRAY(bin->imports, bin->num_imports, n00b_pe_import_t);

    n00b_pe_import_t *imp = &bin->imports[bin->num_imports++];

    imp->name = n00b_string_from_cstr(dll_name);

    return imp;
}

n00b_pe_imported_func_t *
n00b_pe_add_imported_func(n00b_pe_import_t *imp,
                          const char *name, uint16_t hint)
{
    GROW_ARRAY(imp->functions, imp->num_functions, n00b_pe_imported_func_t);

    n00b_pe_imported_func_t *f = &imp->functions[imp->num_functions++];

    f->name = n00b_string_from_cstr(name);
    f->hint = hint;

    return f;
}

n00b_pe_imported_func_t *
n00b_pe_add_imported_func_ordinal(n00b_pe_import_t *imp, uint16_t ordinal)
{
    GROW_ARRAY(imp->functions, imp->num_functions, n00b_pe_imported_func_t);

    n00b_pe_imported_func_t *f = &imp->functions[imp->num_functions++];

    f->ordinal    = ordinal;
    f->is_ordinal = true;

    return f;
}

// ============================================================================
// Export management
// ============================================================================

n00b_pe_exported_func_t *
n00b_pe_add_export(n00b_pe_binary_t *bin, const char *name,
                   uint32_t rva, uint32_t ordinal)
{
    if (!bin->export_info) {
        bin->export_info = n00b_alloc(n00b_pe_export_info_t);
    }

    n00b_pe_export_info_t *ei = bin->export_info;

    GROW_ARRAY(ei->functions, ei->num_functions, n00b_pe_exported_func_t);

    n00b_pe_exported_func_t *f = &ei->functions[ei->num_functions++];

    if (name) {
        f->name = n00b_string_from_cstr(name);
    }

    f->rva     = rva;
    f->ordinal = ordinal;

    return f;
}

void
n00b_pe_set_export_name(n00b_pe_binary_t *bin, const char *name)
{
    if (!bin->export_info) {
        bin->export_info = n00b_alloc(n00b_pe_export_info_t);
    }

    bin->export_info->name = n00b_string_from_cstr(name);
}

// ============================================================================
// Relocation management
// ============================================================================

void
n00b_pe_add_relocation(n00b_pe_binary_t *bin, uint32_t rva, uint8_t type)
{
    GROW_ARRAY(bin->relocations, bin->num_relocations, n00b_pe_relocation_t);

    n00b_pe_relocation_t *r = &bin->relocations[bin->num_relocations++];

    r->rva  = rva;
    r->type = type;
}

// ============================================================================
// Mutation APIs
// ============================================================================

void
n00b_pe_remove_section(n00b_pe_binary_t *bin, const char *name)
{
    if (!bin || !name) {
        return;
    }

    for (uint32_t i = 0; i < bin->num_sections; i++) {
        if (bin->sections[i].name
            && strcmp(bin->sections[i].name->data, name) == 0) {
            // Shift remaining sections down.
            for (uint32_t j = i; j + 1 < bin->num_sections; j++) {
                bin->sections[j] = bin->sections[j + 1];
            }

            bin->num_sections--;
            memset(&bin->sections[bin->num_sections], 0,
                   sizeof(n00b_pe_section_t));

            return;
        }
    }
}

void
n00b_pe_remove_import(n00b_pe_binary_t *bin, const char *dll_name)
{
    if (!bin || !dll_name) {
        return;
    }

    for (uint32_t i = 0; i < bin->num_imports; i++) {
        if (bin->imports[i].name
            && strcasecmp(bin->imports[i].name->data, dll_name) == 0) {
            for (uint32_t j = i; j + 1 < bin->num_imports; j++) {
                bin->imports[j] = bin->imports[j + 1];
            }

            bin->num_imports--;
            memset(&bin->imports[bin->num_imports], 0,
                   sizeof(n00b_pe_import_t));

            return;
        }
    }
}

void
n00b_pe_remove_all_imports(n00b_pe_binary_t *bin)
{
    if (!bin) {
        return;
    }

    bin->imports     = nullptr;
    bin->num_imports = 0;
}

void
n00b_pe_remove_export(n00b_pe_binary_t *bin, const char *func_name)
{
    if (!bin || !func_name || !bin->export_info) {
        return;
    }

    n00b_pe_export_info_t *ei = bin->export_info;

    for (uint32_t i = 0; i < ei->num_functions; i++) {
        if (ei->functions[i].name
            && strcmp(ei->functions[i].name->data, func_name) == 0) {
            for (uint32_t j = i; j + 1 < ei->num_functions; j++) {
                ei->functions[j] = ei->functions[j + 1];
            }

            ei->num_functions--;
            memset(&ei->functions[ei->num_functions], 0,
                   sizeof(n00b_pe_exported_func_t));

            return;
        }
    }
}

n00b_pe_tls_t *
n00b_pe_set_tls(n00b_pe_binary_t *bin)
{
    if (!bin) {
        return nullptr;
    }

    if (!bin->tls) {
        bin->tls = n00b_alloc(n00b_pe_tls_t);
    }

    return bin->tls;
}

void
n00b_pe_remove_tls(n00b_pe_binary_t *bin)
{
    if (!bin) {
        return;
    }

    bin->tls = nullptr;
}

void
n00b_pe_add_tls_callback(n00b_pe_binary_t *bin, uint64_t callback_va)
{
    if (!bin) {
        return;
    }

    if (!bin->tls) {
        bin->tls = n00b_alloc(n00b_pe_tls_t);
    }

    n00b_pe_tls_t *tls = bin->tls;

    GROW_ARRAY(tls->callbacks, tls->num_callbacks, uint64_t);
    tls->callbacks[tls->num_callbacks++] = callback_va;
}

/// Check if a section name matches a synthetic section that the builder
/// regenerates from the import/export/relocation arrays.
static bool
is_synthetic_section(const char *name)
{
    return strcmp(name, ".idata") == 0
        || strcmp(name, ".edata") == 0
        || strcmp(name, ".reloc") == 0;
}

void
n00b_pe_strip_synthetic_sections(n00b_pe_binary_t *bin)
{
    if (!bin) {
        return;
    }

    uint32_t dst = 0;

    for (uint32_t src = 0; src < bin->num_sections; src++) {
        if (bin->sections[src].name
            && is_synthetic_section(bin->sections[src].name->data)) {
            continue;
        }

        if (dst != src) {
            bin->sections[dst] = bin->sections[src];
        }

        dst++;
    }

    // Zero out trailing slots.
    for (uint32_t i = dst; i < bin->num_sections; i++) {
        memset(&bin->sections[i], 0, sizeof(n00b_pe_section_t));
    }

    bin->num_sections = dst;
}

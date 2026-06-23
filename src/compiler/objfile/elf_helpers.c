#include "compiler/objfile/elf_build.h"
#include "text/strings/string_ops.h"

// ============================================================================
// Binary creation
// ============================================================================

n00b_elf_binary_t *
n00b_elf_binary_new(uint16_t type, uint16_t machine) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_elf_binary_t *bin = n00b_alloc_with_opts(
        n00b_elf_binary_t,
        &(n00b_alloc_opts_t){ .allocator = allocator });

    *bin = (typeof(*bin)){};
    bin->allocator = allocator;

    // ELF ident.
    bin->header.ident[EI_MAG0]    = 0x7f;
    bin->header.ident[EI_MAG1]    = 'E';
    bin->header.ident[EI_MAG2]    = 'L';
    bin->header.ident[EI_MAG3]    = 'F';
    bin->header.ident[EI_CLASS]   = ELFCLASS64;
    bin->header.ident[EI_DATA]    = ELFDATA2LSB;
    bin->header.ident[EI_VERSION] = EV_CURRENT;

    bin->header.type      = type;
    bin->header.machine   = machine;
    bin->header.version   = EV_CURRENT;
    bin->header.ehsize    = 64;   // sizeof(n00b_elf64_ehdr_t)
    bin->header.phentsize = 56;   // sizeof(n00b_elf64_phdr_t)
    bin->header.shentsize = 64;   // sizeof(n00b_elf64_shdr_t)

    return bin;
}

// ============================================================================
// Array growth helpers
// ============================================================================

// Grow an array by one element, copy old data, return pointer to new slot.
// Uses the "alloc new + memcpy old + abandon old" pattern from the parser.

// Only reallocate when count is 0 or a power of 2 (i.e. at capacity
// boundary).  Allocations double each time, giving amortized O(1) growth.
#define GROW_ARRAY(bin, field, count_field, elem_type, alloc)                 \
    do {                                                                      \
        uint32_t _bl_old_count = (bin)->count_field;                          \
        uint32_t _bl_new_count = _bl_old_count + 1;                           \
        bool _bl_need_alloc = (_bl_old_count == 0)                            \
                           || (_bl_old_count & (_bl_old_count - 1)) == 0;     \
        if (_bl_need_alloc) {                                                 \
            uint32_t _bl_cap = _bl_old_count == 0 ? 4 : _bl_old_count * 2;    \
            elem_type *_bl_new_arr = n00b_alloc_array_with_opts(              \
                elem_type,                                                    \
                _bl_cap,                                                      \
                &(n00b_alloc_opts_t){ .allocator = (alloc) });                \
            if (_bl_old_count > 0) {                                          \
                memcpy(_bl_new_arr, (bin)->field,                             \
                       _bl_old_count * sizeof(elem_type));                    \
            }                                                                 \
            (bin)->field = _bl_new_arr;                                       \
        }                                                                     \
        (bin)->count_field = _bl_new_count;                                   \
    } while (0)

static inline n00b_allocator_t *
elf_helper_allocator(n00b_elf_binary_t *bin, n00b_allocator_t *allocator)
{
    if (allocator != nullptr) {
        return allocator;
    }
    return bin == nullptr ? nullptr : bin->allocator;
}

// ============================================================================
// Section management
// ============================================================================

n00b_elf_section_t *
n00b_elf_add_section(n00b_elf_binary_t *bin, n00b_string_t *name,
                     uint32_t type, uint64_t flags) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    allocator = elf_helper_allocator(bin, allocator);
    GROW_ARRAY(bin, sections, num_sections, n00b_elf_section_t, allocator);

    n00b_elf_section_t *sec = &bin->sections[bin->num_sections - 1];
    *sec = (typeof(*sec)){};

    if (name != nullptr) {
        sec->name = n00b_string_from_raw(name->data,
                                         (int64_t)name->u8_bytes,
                                         .allocator = allocator);
    }

    sec->type  = type;
    sec->flags = flags;

    return sec;
}

void
n00b_elf_remove_section(n00b_elf_binary_t *bin, n00b_string_t *name) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (bin == nullptr || name == nullptr || bin->num_sections == 0) {
        return;
    }
    allocator = elf_helper_allocator(bin, allocator);

    uint32_t found = UINT32_MAX;

    for (uint32_t i = 0; i < bin->num_sections; i++) {
        if (bin->sections[i].name != nullptr
            && n00b_unicode_str_eq(bin->sections[i].name, name)) {
            found = i;
            break;
        }
    }

    if (found == UINT32_MAX) {
        return;
    }

    uint32_t new_count = bin->num_sections - 1;

    if (new_count == 0) {
        bin->sections     = nullptr;
        bin->num_sections = 0;
        return;
    }

    n00b_elf_section_t *new_arr = n00b_alloc_array_with_opts(
        n00b_elf_section_t,
        new_count,
        &(n00b_alloc_opts_t){ .allocator = allocator });

    if (found > 0) {
        memcpy(new_arr, bin->sections, found * sizeof(n00b_elf_section_t));
    }

    if (found < new_count) {
        memcpy(new_arr + found, bin->sections + found + 1,
               (new_count - found) * sizeof(n00b_elf_section_t));
    }

    bin->sections     = new_arr;
    bin->num_sections = new_count;
}

// ============================================================================
// Segment management
// ============================================================================

n00b_elf_segment_t *
n00b_elf_add_segment(n00b_elf_binary_t *bin, uint32_t type,
                     uint32_t flags) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    allocator = elf_helper_allocator(bin, allocator);
    GROW_ARRAY(bin, segments, num_segments, n00b_elf_segment_t, allocator);

    n00b_elf_segment_t *seg = &bin->segments[bin->num_segments - 1];
    *seg = (typeof(*seg)){};

    seg->type  = type;
    seg->flags = flags;

    return seg;
}

// ============================================================================
// Symbol management
// ============================================================================

static n00b_elf_symbol_t *
add_symbol(n00b_elf_symbol_t **syms, uint32_t *count,
           n00b_string_t *name, uint64_t value, uint64_t size,
           uint8_t bind, uint8_t type, uint16_t shndx,
           n00b_allocator_t *allocator)
{
    uint32_t old_count = *count;
    uint32_t new_count = old_count + 1;

    n00b_elf_symbol_t *new_arr = n00b_alloc_array_with_opts(
        n00b_elf_symbol_t,
        new_count,
        &(n00b_alloc_opts_t){ .allocator = allocator });

    if (old_count > 0) {
        memcpy(new_arr, *syms, old_count * sizeof(n00b_elf_symbol_t));
    }

    *syms  = new_arr;
    *count = new_count;

    n00b_elf_symbol_t *sym = &new_arr[new_count - 1];
    *sym = (typeof(*sym)){};

    if (name != nullptr) {
        sym->name = n00b_string_from_raw(name->data,
                                         (int64_t)name->u8_bytes,
                                         .allocator = allocator);
    }

    sym->info  = N00B_ELF64_ST_INFO(bind, type);
    sym->shndx = shndx;
    sym->value = value;
    sym->size  = size;

    return sym;
}

n00b_elf_symbol_t *
n00b_elf_add_symtab_symbol(n00b_elf_binary_t *bin,
    n00b_string_t *name, uint64_t value, uint64_t size,
    uint8_t bind, uint8_t type, uint16_t shndx) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    allocator = elf_helper_allocator(bin, allocator);
    return add_symbol(&bin->symtab_symbols, &bin->num_symtab,
                      name, value, size, bind, type, shndx, allocator);
}

n00b_elf_symbol_t *
n00b_elf_add_dynsym_symbol(n00b_elf_binary_t *bin,
    n00b_string_t *name, uint64_t value, uint64_t size,
    uint8_t bind, uint8_t type, uint16_t shndx) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    allocator = elf_helper_allocator(bin, allocator);
    return add_symbol(&bin->dynsym_symbols, &bin->num_dynsym,
                      name, value, size, bind, type, shndx, allocator);
}

// ============================================================================
// Relocation management
// ============================================================================

n00b_elf_relocation_t *
n00b_elf_add_relocation(n00b_elf_binary_t *bin,
    uint64_t offset, uint32_t sym_index, uint32_t rel_type,
    int64_t addend) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    allocator = elf_helper_allocator(bin, allocator);
    GROW_ARRAY(bin,
               relocations,
               num_relocations,
               n00b_elf_relocation_t,
               allocator);

    n00b_elf_relocation_t *rel = &bin->relocations[bin->num_relocations - 1];
    *rel = (typeof(*rel)){};

    rel->offset     = offset;
    rel->info       = N00B_ELF64_R_INFO(sym_index, rel_type);
    rel->addend     = addend;
    rel->has_addend = true;

    return rel;
}

// ============================================================================
// Dynamic entry management
// ============================================================================

n00b_elf_dynamic_t *
n00b_elf_add_dynamic(n00b_elf_binary_t *bin, int64_t tag,
                     uint64_t value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    allocator = elf_helper_allocator(bin, allocator);
    GROW_ARRAY(bin, dynamic_entries, num_dynamic, n00b_elf_dynamic_t, allocator);

    n00b_elf_dynamic_t *dyn = &bin->dynamic_entries[bin->num_dynamic - 1];

    dyn->tag   = tag;
    dyn->value = value;

    return dyn;
}

void
n00b_elf_set_dynamic(n00b_elf_binary_t *bin, int64_t tag,
                     uint64_t value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    for (uint32_t i = 0; i < bin->num_dynamic; i++) {
        if (bin->dynamic_entries[i].tag == tag) {
            bin->dynamic_entries[i].value = value;
            return;
        }
    }

    n00b_elf_add_dynamic(bin, tag, value, .allocator = allocator);
}

// ============================================================================
// Note management
// ============================================================================

n00b_elf_note_t *
n00b_elf_add_note(n00b_elf_binary_t *bin,
    n00b_string_t *name, uint32_t type, n00b_buffer_t *desc) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    allocator = elf_helper_allocator(bin, allocator);
    GROW_ARRAY(bin, notes, num_notes, n00b_elf_note_t, allocator);

    n00b_elf_note_t *note = &bin->notes[bin->num_notes - 1];
    *note = (typeof(*note)){};

    if (name != nullptr) {
        note->name = n00b_string_from_raw(name->data,
                                          (int64_t)name->u8_bytes,
                                          .allocator = allocator);
    }

    note->type = type;
    note->desc = desc;

    return note;
}

// ============================================================================
// Convenience
// ============================================================================

void
n00b_elf_set_interpreter(n00b_elf_binary_t *bin, n00b_string_t *path) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (path != nullptr) {
        allocator = elf_helper_allocator(bin, allocator);
        bin->interpreter = n00b_string_from_raw(path->data,
                                                (int64_t)path->u8_bytes,
                                                .allocator = allocator);
    }
}

void
n00b_elf_set_entry(n00b_elf_binary_t *bin, uint64_t entry)
{
    bin->header.entry = entry;
}

uint16_t
n00b_elf_section_index(n00b_elf_binary_t *bin, n00b_string_t *name)
{
    for (uint32_t i = 0; i < bin->num_sections; i++) {
        if (bin->sections[i].name != nullptr
            && n00b_unicode_str_eq(bin->sections[i].name, name)) {
            // +1 because the builder inserts SHT_NULL at index 0.
            return (uint16_t)(i + 1);
        }
    }

    return SHN_UNDEF;
}

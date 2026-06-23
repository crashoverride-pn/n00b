/**
 * @file n00b_elf_build.h
 * @brief ELF binary builder — struct helpers and serialization.
 *
 * Provides functions to create and populate `n00b_elf_binary_t` structs
 * from scratch, then serialize them to `n00b_buffer_t *` via
 * `n00b_elf_build()`.
 */
#pragma once

#include "compiler/objfile/elf.h"
#include "compiler/objfile/writer.h"
#include "adt/result.h"

// ============================================================================
// Binary creation
// ============================================================================

/**
 * @brief Create a new empty ELF64 binary struct.
 *
 * Initializes the ELF header with ELFCLASS64, ELFDATA2LSB, EV_CURRENT,
 * and sets ehsize/phentsize/shentsize to standard sizes.
 *
 * @param type     ELF object type (ET_EXEC, ET_DYN, ET_REL, etc.).
 * @param machine  Machine type (EM_X86_64, EM_AARCH64, etc.).
 * @kw allocator   Optional allocator for the binary and helper-owned data.
 */
extern n00b_elf_binary_t *n00b_elf_binary_new(uint16_t type,
                                               uint16_t machine) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

// ============================================================================
// Section management
// ============================================================================

/**
 * @brief Add a new section to the binary.
 * @kw allocator Optional allocator for helper-owned growth and name copies;
 *               nullptr uses @p bin's allocator.
 * @return Pointer to the new section (within the binary's sections array).
 */
extern n00b_elf_section_t *n00b_elf_add_section(n00b_elf_binary_t *bin,
                                                 n00b_string_t *name,
                                                 uint32_t type,
                                                 uint64_t flags) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/// Remove a section by name.  No-op if not found.
/// @kw allocator Optional allocator for replacement section storage;
///               nullptr uses @p bin's allocator.
extern void n00b_elf_remove_section(n00b_elf_binary_t *bin,
                                    n00b_string_t *name) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

// ============================================================================
// Segment management
// ============================================================================

/**
 * @brief Add a new segment to the binary.
 * @kw allocator Optional allocator for helper-owned growth; nullptr uses
 *               @p bin's allocator.
 * @return Pointer to the new segment.
 */
extern n00b_elf_segment_t *n00b_elf_add_segment(n00b_elf_binary_t *bin,
                                                 uint32_t type,
                                                 uint32_t flags) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

// ============================================================================
// Symbol management
// ============================================================================

/**
 * @brief Add a symbol to the static symbol table (.symtab).
 * @kw allocator Optional allocator for helper-owned growth and name copies;
 *               nullptr uses @p bin's allocator.
 */
extern n00b_elf_symbol_t *n00b_elf_add_symtab_symbol(n00b_elf_binary_t *bin,
    n00b_string_t *name, uint64_t value, uint64_t size,
    uint8_t bind, uint8_t type, uint16_t shndx) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Add a symbol to the dynamic symbol table (.dynsym).
 * @kw allocator Optional allocator for helper-owned growth and name copies;
 *               nullptr uses @p bin's allocator.
 */
extern n00b_elf_symbol_t *n00b_elf_add_dynsym_symbol(n00b_elf_binary_t *bin,
    n00b_string_t *name, uint64_t value, uint64_t size,
    uint8_t bind, uint8_t type, uint16_t shndx) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

// ============================================================================
// Relocation management
// ============================================================================

/**
 * @brief Add a relocation record.
 * @kw allocator Optional allocator for helper-owned growth; nullptr uses
 *               @p bin's allocator.
 */
extern n00b_elf_relocation_t *n00b_elf_add_relocation(n00b_elf_binary_t *bin,
    uint64_t offset, uint32_t sym_index, uint32_t rel_type,
    int64_t addend) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

// ============================================================================
// Dynamic entry management
// ============================================================================

/**
 * @brief Add a dynamic table entry.
 * @kw allocator Optional allocator for helper-owned growth; nullptr uses
 *               @p bin's allocator.
 */
extern n00b_elf_dynamic_t *n00b_elf_add_dynamic(n00b_elf_binary_t *bin,
    int64_t tag, uint64_t value) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/// Set the value for an existing dynamic tag, or add a new entry if not found.
/// @kw allocator Optional allocator if a new dynamic entry is added; nullptr
///               uses @p bin's allocator.
extern void n00b_elf_set_dynamic(n00b_elf_binary_t *bin,
    int64_t tag, uint64_t value) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

// ============================================================================
// Note management
// ============================================================================

/**
 * @brief Add an ELF note.
 * @kw allocator Optional allocator for helper-owned growth and name copies;
 *               nullptr uses @p bin's allocator.
 */
extern n00b_elf_note_t *n00b_elf_add_note(n00b_elf_binary_t *bin,
    n00b_string_t *name, uint32_t type, n00b_buffer_t *desc) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

// ============================================================================
// Convenience
// ============================================================================

/**
 * @brief Set the PT_INTERP path string.
 * @kw allocator Optional allocator for the copied string; nullptr uses
 *               @p bin's allocator.
 */
extern void     n00b_elf_set_interpreter(n00b_elf_binary_t *bin,
                                          n00b_string_t *path) _kargs {
    n00b_allocator_t *allocator = nullptr;
};
extern void     n00b_elf_set_entry(n00b_elf_binary_t *bin, uint64_t entry);
extern uint16_t n00b_elf_section_index(n00b_elf_binary_t *bin,
                                        n00b_string_t *name);

// ============================================================================
// Builder
// ============================================================================

/**
 * @brief Serialize the ELF binary struct to a buffer.
 *
 * Auto-generates `.shstrtab`, `.strtab`, `.symtab`, `.dynstr`, `.dynsym`,
 * `.dynamic`, `.rela.dyn`, `.gnu.hash`, `.interp`, `.note.*`, and version
 * sections as needed.  Computes layout, assigns offsets, fixes up headers.
 *
 * @param bin       Populated ELF binary struct.
 * @kw allocator    Optional allocator for builder scratch storage and the
 *                  returned object buffer.
 * @return Ok(buffer) or Err(N00B_ERR_BUILD).
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_elf_build(n00b_elf_binary_t *bin) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

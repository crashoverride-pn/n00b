/**
 * @file n00b_dwarf.h
 * @brief DWARF debug information reader, writer, and query API.
 *
 * Provides types and functions for:
 * - Parsing DWARF debug info from ELF and Mach-O binaries
 * - Querying functions, types, and line numbers
 * - Generating C header text from DWARF type definitions
 * - Building DWARF sections programmatically
 *
 * Supports DWARF versions 2 through 5, 32-bit and 64-bit DWARF format.
 */
#pragma once

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "compiler/objfile/types.h"
#include "compiler/objfile/dwarf_types.h"
#include "compiler/objfile/writer.h"

// Forward declarations for format-specific binaries.
typedef struct n00b_elf_binary   n00b_elf_binary_t;
typedef struct n00b_macho_binary n00b_macho_binary_t;

// ============================================================================
// Abbreviation table (internal, exposed for testing)
// ============================================================================

/// Single attribute specification in an abbreviation entry.
typedef struct {
    uint64_t name;           ///< N00B_DW_AT_*
    uint64_t form;           ///< N00B_DW_FORM_*
    int64_t  implicit_const; ///< Value for N00B_DW_FORM_implicit_const.
} n00b_dwarf_abbrev_attr_t;

/// One abbreviation entry (code → tag + attrs).
typedef struct {
    uint64_t                 code;
    uint64_t                 tag;          ///< N00B_DW_TAG_*
    bool                     has_children;
    n00b_dwarf_abbrev_attr_t *attrs;
    size_t                   attr_count;
} n00b_dwarf_abbrev_t;

/// A complete abbreviation table (parsed from .debug_abbrev at one offset).
typedef struct {
    n00b_dwarf_abbrev_t *entries;
    size_t               count;
    size_t               capacity;
} n00b_dwarf_abbrev_table_t;

// ============================================================================
// Parsed attribute value
// ============================================================================

/// A decoded DWARF attribute: name + form + value.
typedef struct {
    uint64_t name;   ///< N00B_DW_AT_*
    uint64_t form;   ///< N00B_DW_FORM_*
    union [[n00b::raw_union]] {
        uint64_t       u64;
        int64_t        s64;
        const char    *str;
        struct {
            const uint8_t *data;
            size_t         size;
        } block;
    };
} n00b_dwarf_attr_t;

// ============================================================================
// Debug Information Entry
// ============================================================================

/// A parsed DIE with its tag, attributes, and offset information.
typedef struct {
    uint64_t          tag;          ///< N00B_DW_TAG_*
    bool              has_children;
    size_t            offset;       ///< Absolute offset in .debug_info.
    size_t            next_offset;  ///< Offset past this DIE (for skipping).
    n00b_dwarf_attr_t *attrs;
    size_t            attr_count;
} n00b_dwarf_die_t;

// ============================================================================
// Compilation Unit header
// ============================================================================

/// Parsed compilation unit header from .debug_info.
typedef struct {
    uint64_t unit_length;
    uint16_t version;        ///< DWARF version (2-5).
    uint8_t  unit_type;      ///< N00B_DW_UT_* (DWARF 5; 0 for earlier).
    uint8_t  address_size;   ///< Pointer size in bytes (4 or 8).
    uint64_t abbrev_offset;  ///< Offset into .debug_abbrev.
    bool     is_64bit;       ///< true if 64-bit DWARF format.
    size_t   cu_offset;      ///< Start of this CU in .debug_info.
    size_t   header_size;    ///< Byte length of the CU header.
    size_t   die_offset;     ///< Offset of the first DIE.
    // DWARF 5 base values (parsed from root DIE).
    uint64_t str_offsets_base;
    uint64_t addr_base;
    bool     bases_parsed;
} n00b_dwarf_cu_t;

// ============================================================================
// Line number entry
// ============================================================================

/// One decoded row from the .debug_line state machine.
typedef struct {
    uint64_t    address;
    const char *file;
    uint32_t    line;
    uint16_t    column;
    bool        is_stmt;
    bool        end_sequence;
} n00b_dwarf_line_entry_t;

// ============================================================================
// Type definitions (for codegen)
// ============================================================================

/// Kind of type definition.
typedef enum {
    N00B_DWARF_TYPE_STRUCT,
    N00B_DWARF_TYPE_CLASS,
    N00B_DWARF_TYPE_UNION,
    N00B_DWARF_TYPE_ENUM,
    N00B_DWARF_TYPE_TYPEDEF,
    N00B_DWARF_TYPE_ARRAY,
    N00B_DWARF_TYPE_POINTER,
    N00B_DWARF_TYPE_BASE,
} n00b_dwarf_type_kind_t;

/// A struct/union/class member.
typedef struct {
    n00b_string_t *name;
    n00b_string_t *type_name;
    uint64_t       offset;     ///< Byte offset within parent.
    uint64_t       size;       ///< Size in bytes (0 if unknown).
    uint32_t       bit_size;   ///< Bit field width (0 = not a bitfield).
    uint32_t       bit_offset; ///< Bit offset within storage unit.
} n00b_dwarf_member_t;

/// An enumeration constant.
typedef struct {
    n00b_string_t *name;
    int64_t        value;
} n00b_dwarf_enumerator_t;

/// A complete type definition extracted from DWARF.
typedef struct {
    n00b_dwarf_type_kind_t  kind;
    n00b_string_t          *name;
    n00b_string_t          *qualified_name;
    uint64_t                byte_size;
    uint64_t                alignment;
    // Members (struct/union/class).
    n00b_dwarf_member_t    *members;
    size_t                  num_members;
    // Enumerators (enum).
    n00b_dwarf_enumerator_t *enumerators;
    size_t                   num_enumerators;
    // Typedef target / pointer target / array element type.
    n00b_string_t           *aliased_type;
    // Encoding for base types.
    uint64_t                 encoding;   ///< N00B_DW_ATE_*
    // Source location.
    size_t                   die_offset;
} n00b_dwarf_type_def_t;

// ============================================================================
// Function info
// ============================================================================

/// Extracted information about a function/subprogram.
typedef struct {
    n00b_string_t  *name;
    n00b_string_t  *linkage_name;
    uint64_t        low_pc;
    uint64_t        high_pc;
    n00b_string_t **param_names;
    n00b_string_t **param_types;
    size_t          param_count;
    n00b_string_t  *return_type;
    n00b_string_t  *source_file;
    uint32_t        source_line;
    bool            is_external;
} n00b_dwarf_function_t;

// ============================================================================
// Top-level DWARF info container
// ============================================================================

/// All parsed DWARF data for a binary.
typedef struct {
    n00b_dwarf_cu_t         *cus;
    size_t                   num_cus;

    n00b_dwarf_function_t   *functions;
    size_t                   num_functions;
    bool                     func_index_built;

    n00b_dwarf_type_def_t   *types;
    size_t                   num_types;
    bool                     type_index_built;

    n00b_dwarf_line_entry_t *line_entries;
    size_t                   num_line_entries;
    bool                     lines_parsed;

    // Abbreviation table cache (indexed by offset).
    n00b_dwarf_abbrev_table_t **abbrev_tables;
    size_t                      abbrev_table_count;
    size_t                      abbrev_table_cap;

    // Raw section data (kept for lazy/on-demand parsing).
    const uint8_t *debug_info;          size_t debug_info_size;
    const uint8_t *debug_abbrev;        size_t debug_abbrev_size;
    const uint8_t *debug_str;           size_t debug_str_size;
    const uint8_t *debug_line;          size_t debug_line_size;
    const uint8_t *debug_str_offsets;   size_t debug_str_offsets_size;
    const uint8_t *debug_addr;          size_t debug_addr_size;
    const uint8_t *debug_ranges;        size_t debug_ranges_size;
    const uint8_t *debug_rnglists;      size_t debug_rnglists_size;
    const uint8_t *debug_line_str;      size_t debug_line_str_size;
    const uint8_t *debug_loclists;      size_t debug_loclists_size;
} n00b_dwarf_info_t;

// ============================================================================
// Core reader API (Phase 10b)
// ============================================================================

/**
 * @brief Parse DWARF from an ELF binary.
 *
 * Extracts `.debug_info`, `.debug_abbrev`, `.debug_str`, and other debug
 * sections, parses all compilation unit headers.
 */
extern n00b_result_t(n00b_dwarf_info_t *)
    n00b_dwarf_parse_elf(n00b_elf_binary_t *bin);

/**
 * @brief Parse DWARF from a Mach-O binary.
 *
 * Looks for `__debug_info`, `__debug_abbrev`, etc. in the `__DWARF` segment.
 */
extern n00b_result_t(n00b_dwarf_info_t *)
    n00b_dwarf_parse_macho(n00b_macho_binary_t *bin);

/**
 * @brief Parse DWARF from raw section byte arrays.
 *
 * At minimum, `debug_info` and `debug_abbrev` must be provided.
 */
extern n00b_result_t(n00b_dwarf_info_t *)
    n00b_dwarf_parse_sections(const uint8_t *debug_info,   size_t info_size,
                              const uint8_t *debug_abbrev, size_t abbrev_size,
                              const uint8_t *debug_str,    size_t str_size,
                              const uint8_t *debug_line,   size_t line_size);

/// Check whether an ELF binary has DWARF debug info.
extern bool n00b_dwarf_has_info(n00b_elf_binary_t *bin);

/// Check whether a Mach-O binary has DWARF debug info.
extern bool n00b_dwarf_has_info_macho(n00b_macho_binary_t *bin);

// ---- Low-level parsing (exposed for testing) ----

/// Parse an abbreviation table at the given offset in .debug_abbrev.
extern n00b_dwarf_abbrev_table_t *
    n00b_dwarf_parse_abbrev_table(const uint8_t *abbrev_data,
                                  size_t         abbrev_size,
                                  uint64_t       offset);

/// Parse a CU header at the given offset in .debug_info.
extern bool n00b_dwarf_parse_cu_header(const uint8_t *info_data,
                                       size_t         info_size,
                                       size_t         offset,
                                       n00b_dwarf_cu_t *out);

/// Parse a single DIE at the given offset.
extern bool n00b_dwarf_parse_die(n00b_dwarf_info_t        *info,
                                 n00b_dwarf_abbrev_table_t *abbrev_table,
                                 const n00b_dwarf_cu_t     *cu,
                                 size_t                     offset,
                                 n00b_dwarf_die_t          *out);

/// Skip past a DIE (and its children if any), returning the next offset.
extern size_t n00b_dwarf_skip_die(n00b_dwarf_info_t         *info,
                                  n00b_dwarf_abbrev_table_t *abbrev_table,
                                  const n00b_dwarf_cu_t     *cu,
                                  size_t                     offset);

/// Look up an attribute in a parsed DIE by name.
extern const n00b_dwarf_attr_t *
    n00b_dwarf_die_get_attr(const n00b_dwarf_die_t *die, uint64_t name);

/// Find an abbreviation by code in a parsed table.
extern const n00b_dwarf_abbrev_t *
    n00b_dwarf_abbrev_find(const n00b_dwarf_abbrev_table_t *table,
                           uint64_t code);

// ============================================================================
// Query API (Phase 10c)
// ============================================================================

/// Build the function index (walks all CUs).  Called lazily by query functions.
extern void n00b_dwarf_build_func_index(n00b_dwarf_info_t *info);

/// Build the type index (walks all CUs).  Called lazily by query functions.
extern void n00b_dwarf_build_type_index(n00b_dwarf_info_t *info);

/// Find a function by address (binary search over indexed subprograms).
extern n00b_dwarf_function_t *
    n00b_dwarf_function_at_addr(n00b_dwarf_info_t *info, uint64_t addr);

/// Find a function by name (or linkage name).
extern n00b_dwarf_function_t *
    n00b_dwarf_function_by_name(n00b_dwarf_info_t *info, const char *name);

/// Find a type definition by name.
extern n00b_dwarf_type_def_t *
    n00b_dwarf_type_by_name(n00b_dwarf_info_t *info, const char *name);

// ============================================================================
// Code generation (Phase 10d)
// ============================================================================

/// Generate a C struct/union definition from a DWARF type.
extern n00b_string_t *n00b_dwarf_generate_struct(const n00b_dwarf_type_def_t *type);

/// Generate a C enum definition from a DWARF type.
extern n00b_string_t *n00b_dwarf_generate_enum(const n00b_dwarf_type_def_t *type);

/// Generate a C typedef from a DWARF type.
extern n00b_string_t *n00b_dwarf_generate_typedef(const n00b_dwarf_type_def_t *type);

/// Generate a complete C header from all types in the DWARF info.
extern n00b_string_t *n00b_dwarf_generate_header(n00b_dwarf_info_t *info);

// ============================================================================
// Line number table (Phase 10e)
// ============================================================================

/// Parse the .debug_line section, populating `info->line_entries`.
extern n00b_result_t(bool) n00b_dwarf_parse_line_table(n00b_dwarf_info_t *info);

/// Find the line entry whose address range contains `addr`.
extern n00b_dwarf_line_entry_t *
    n00b_dwarf_line_at_addr(n00b_dwarf_info_t *info, uint64_t addr);

// ============================================================================
// DWARF builder types (Phase 10f)
// ============================================================================

/// An attribute to emit when building DWARF.
typedef struct {
    uint64_t name;   ///< N00B_DW_AT_*
    uint64_t form;   ///< N00B_DW_FORM_*
    union [[n00b::raw_union]] {
        uint64_t       u64;
        int64_t        s64;
        const char    *str;
        struct {
            const uint8_t *data;
            size_t         size;
        } block;
    };
} n00b_dwarf_build_attr_t;

/// A DIE to emit (tree node).
typedef struct n00b_dwarf_build_die {
    uint64_t                     tag;   ///< N00B_DW_TAG_*
    n00b_dwarf_build_attr_t     *attrs;
    size_t                       attr_count;
    size_t                       attr_cap;
    struct n00b_dwarf_build_die *children;
    size_t                       num_children;
    size_t                       children_cap;
} n00b_dwarf_build_die_t;

/// A compilation unit to emit.
typedef struct {
    uint8_t                address_size;  ///< 4 or 8.
    n00b_dwarf_build_die_t root;          ///< N00B_DW_TAG_compile_unit root DIE.
} n00b_dwarf_build_cu_t;

/// Serialized DWARF sections (output of builder).
typedef struct {
    n00b_buffer_t *debug_info;
    n00b_buffer_t *debug_abbrev;
    n00b_buffer_t *debug_str;
    n00b_buffer_t *debug_line;   ///< Nullable (only if line program added).
} n00b_dwarf_sections_t;

/// Line program builder types (Phase 10g).
typedef struct {
    n00b_string_t *directory;
} n00b_dwarf_build_dir_t;

typedef struct {
    n00b_string_t *name;
    uint32_t       dir_index;
} n00b_dwarf_build_file_t;

typedef struct {
    uint64_t address;
    uint32_t file_index;   ///< 1-based.
    uint32_t line;
    uint16_t column;
    bool     is_stmt;
    bool     end_sequence;
} n00b_dwarf_build_line_row_t;

typedef struct {
    n00b_dwarf_build_dir_t      *dirs;
    size_t                       num_dirs;
    size_t                       dirs_cap;
    n00b_dwarf_build_file_t     *files;
    size_t                       num_files;
    size_t                       files_cap;
    n00b_dwarf_build_line_row_t *rows;
    size_t                       num_rows;
    size_t                       rows_cap;
    uint8_t                      min_insn_length;  ///< Default 1.
    int8_t                       line_base;         ///< Default -5.
    uint8_t                      line_range;        ///< Default 14.
} n00b_dwarf_build_line_t;

/// Top-level DWARF builder.
typedef struct {
    n00b_dwarf_build_cu_t   *cus;
    size_t                   num_cus;
    size_t                   cus_cap;
    n00b_dwarf_build_line_t *line_program;  ///< Nullable.
} n00b_dwarf_builder_t;

// ============================================================================
// Builder API (Phase 10f)
// ============================================================================

/// Create a new DWARF builder.
extern n00b_dwarf_builder_t *n00b_dwarf_builder_new(void);

/// Add a compilation unit to the builder.  Returns pointer to new CU.
extern n00b_dwarf_build_cu_t *
    n00b_dwarf_builder_add_cu(n00b_dwarf_builder_t *builder,
                              uint8_t address_size);

/// Create a new build DIE with the given tag.
extern n00b_dwarf_build_die_t *n00b_dwarf_build_die_new(uint64_t tag);

/// Add a string attribute (N00B_DW_FORM_strp).
extern void n00b_dwarf_build_die_add_attr_str(n00b_dwarf_build_die_t *die,
                                               uint64_t name,
                                               const char *str);

/// Add an unsigned integer attribute with explicit form.
extern void n00b_dwarf_build_die_add_attr_u64(n00b_dwarf_build_die_t *die,
                                               uint64_t name,
                                               uint64_t form,
                                               uint64_t value);

/// Add an address attribute (N00B_DW_FORM_addr).
extern void n00b_dwarf_build_die_add_attr_addr(n00b_dwarf_build_die_t *die,
                                                uint64_t name,
                                                uint64_t addr);

/// Add a child DIE.
extern void n00b_dwarf_build_die_add_child(n00b_dwarf_build_die_t *parent,
                                            n00b_dwarf_build_die_t *child);

/// Serialize all sections from the builder.
extern n00b_dwarf_sections_t n00b_dwarf_build(n00b_dwarf_builder_t *builder);

// ============================================================================
// Line program builder API (Phase 10g)
// ============================================================================

/// Create a line program and attach it to the builder.
extern n00b_dwarf_build_line_t *
    n00b_dwarf_builder_add_line_program(n00b_dwarf_builder_t *builder);

/// Add a directory entry.
extern void n00b_dwarf_build_line_add_dir(n00b_dwarf_build_line_t *prog,
                                           const char *dir);

/// Add a file entry.  Returns 1-based file index.
extern uint32_t
    n00b_dwarf_build_line_add_file(n00b_dwarf_build_line_t *prog,
                                   const char *name,
                                   uint32_t dir_index);

/// Add a line matrix row.
extern void n00b_dwarf_build_line_add_row(n00b_dwarf_build_line_t *prog,
                                           uint64_t address,
                                           uint32_t file,
                                           uint32_t line,
                                           uint16_t column,
                                           bool     is_stmt);

/// Emit an end-of-sequence marker at the given address.
extern void n00b_dwarf_build_line_end_sequence(n00b_dwarf_build_line_t *prog,
                                                uint64_t address);

// ============================================================================
// ELF / Mach-O integration (Phase 10h)
// ============================================================================

/// Add DWARF debug sections to an ELF binary.
extern void n00b_elf_add_dwarf(n00b_elf_binary_t *bin,
                                n00b_dwarf_sections_t sections);

/// Add DWARF debug sections to a Mach-O binary.
extern void n00b_macho_add_dwarf(n00b_macho_binary_t *bin,
                                  n00b_dwarf_sections_t sections);

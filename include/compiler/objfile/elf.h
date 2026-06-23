/**
 * @file n00b_elf.h
 * @brief High-level parsed ELF64 types and parse API.
 *
 * Provides the fully-parsed ELF binary representation with resolved names,
 * extracted content, and structured access to symbols, relocations, dynamic
 * entries, notes, hash tables, and symbol versioning information.
 */
#pragma once

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/option.h"
#include "adt/result.h"
#include "compiler/objfile/types.h"
#include "compiler/objfile/bstream.h"
#include "compiler/objfile/elf_types.h"

// ============================================================================
// Parsed ELF header
// ============================================================================

typedef struct n00b_elf_header {
    uint8_t       ident[16];
    uint16_t      type;
    uint16_t      machine;
    uint32_t      version;
    uint64_t      entry;
    uint64_t      phoff;
    uint64_t      shoff;
    uint32_t      flags;
    uint16_t      ehsize;
    uint16_t      phentsize;
    uint16_t      phnum;
    uint16_t      shentsize;
    uint16_t      shnum;
    uint16_t      shstrndx;
} n00b_elf_header_t;

// ============================================================================
// Parsed section
// ============================================================================

typedef struct n00b_elf_section {
    n00b_string_t  *name;
    uint32_t        type;
    uint64_t        flags;
    uint64_t        addr;
    uint64_t        offset;
    uint64_t        size;
    uint32_t        link;
    uint32_t        info;
    uint64_t        addralign;
    uint64_t        entsize;
    n00b_buffer_t  *content;     ///< Raw section bytes (nullable for NOBITS).
} n00b_elf_section_t;

// ============================================================================
// Parsed segment
// ============================================================================

typedef struct n00b_elf_segment {
    uint32_t        type;
    uint32_t        flags;
    uint64_t        offset;
    uint64_t        vaddr;
    uint64_t        paddr;
    uint64_t        filesz;
    uint64_t        memsz;
    uint64_t        align;
    n00b_buffer_t  *content;     ///< Raw segment bytes (nullable).
} n00b_elf_segment_t;

// ============================================================================
// Parsed symbol
// ============================================================================

typedef struct n00b_elf_symbol {
    n00b_string_t  *name;
    n00b_string_t  *demangled_name; ///< Auto-demangled (C++/Rust), or nullptr.
    uint8_t         info;
    uint8_t         other;
    uint16_t        shndx;
    uint64_t        value;
    uint64_t        size;
} n00b_elf_symbol_t;

// ============================================================================
// Parsed relocation
// ============================================================================

typedef struct n00b_elf_relocation {
    uint64_t        offset;
    uint64_t        info;
    int64_t         addend;
    bool            has_addend;
} n00b_elf_relocation_t;

// ============================================================================
// Dynamic table entry
// ============================================================================

typedef struct n00b_elf_dynamic {
    int64_t         tag;
    uint64_t        value;
} n00b_elf_dynamic_t;

// ============================================================================
// Note
// ============================================================================

typedef struct n00b_elf_note {
    n00b_string_t  *name;
    uint32_t        type;
    n00b_buffer_t  *desc;
} n00b_elf_note_t;

// ============================================================================
// Core dump note types
// ============================================================================

typedef struct n00b_elf_prstatus {
    int32_t         signal;
    int32_t         pid;
    int32_t         ppid;
    int32_t         pgrp;
    int32_t         sid;
    n00b_buffer_t  *registers;   ///< Raw register state (arch-dependent size).
} n00b_elf_prstatus_t;

typedef struct n00b_elf_prpsinfo {
    uint8_t         state;
    char            sname;
    uint8_t         zombie;
    int8_t          nice;
    int32_t         pid;
    int32_t         ppid;
    int32_t         pgrp;
    int32_t         sid;
    int32_t         uid;
    int32_t         gid;
    char            fname[16];
    char            psargs[80];
} n00b_elf_prpsinfo_t;

typedef struct n00b_elf_auxv_entry {
    uint64_t        type;
    uint64_t        value;
} n00b_elf_auxv_entry_t;

typedef struct n00b_elf_file_entry {
    uint64_t        start;
    uint64_t        end;
    uint64_t        offset;
    n00b_string_t  *name;
} n00b_elf_file_entry_t;

typedef struct n00b_elf_core_info {
    n00b_elf_prstatus_t   *prstatus;
    uint32_t               num_prstatus;
    n00b_elf_prpsinfo_t   *prpsinfo;
    n00b_elf_auxv_entry_t *auxv;
    uint32_t               num_auxv;
    n00b_elf_file_entry_t *files;
    uint32_t               num_files;
} n00b_elf_core_info_t;

// ============================================================================
// GNU hash table
// ============================================================================

typedef struct n00b_elf_gnu_hash {
    uint32_t        nbuckets;
    uint32_t        symoffset;
    uint32_t        bloom_size;
    uint32_t        bloom_shift;
    uint64_t       *bloom;
    uint32_t       *buckets;
    uint32_t       *chains;
    uint32_t        nchains;
} n00b_elf_gnu_hash_t;

// ============================================================================
// SYSV hash table
// ============================================================================

typedef struct n00b_elf_sysv_hash {
    uint32_t        nbucket;
    uint32_t        nchain;
    uint32_t       *buckets;
    uint32_t       *chains;
} n00b_elf_sysv_hash_t;

// ============================================================================
// Symbol versioning
// ============================================================================

typedef struct n00b_elf_symbol_version {
    uint16_t        value;
} n00b_elf_symbol_version_t;

typedef struct n00b_elf_verneed {
    uint16_t        version;
    n00b_string_t  *file;
    uint16_t        cnt;
} n00b_elf_verneed_t;

typedef struct n00b_elf_vernaux {
    uint32_t        hash;
    uint16_t        flags;
    uint16_t        other;
    n00b_string_t  *name;
} n00b_elf_vernaux_t;

typedef struct n00b_elf_verdef {
    uint16_t        version;
    uint16_t        flags;
    uint16_t        ndx;
    uint16_t        cnt;
    uint32_t        hash;
    n00b_string_t  *name;
} n00b_elf_verdef_t;

// ============================================================================
// Top-level ELF binary
// ============================================================================

typedef struct n00b_elf_binary {
    n00b_allocator_t          *allocator;
    n00b_elf_header_t          header;
    n00b_elf_section_t        *sections;
    uint32_t                   num_sections;
    n00b_elf_segment_t        *segments;
    uint32_t                   num_segments;
    n00b_elf_symbol_t         *symtab_symbols;
    uint32_t                   num_symtab;
    n00b_elf_symbol_t         *dynsym_symbols;
    uint32_t                   num_dynsym;
    n00b_elf_relocation_t     *relocations;
    uint32_t                   num_relocations;
    n00b_elf_dynamic_t        *dynamic_entries;
    uint32_t                   num_dynamic;
    n00b_elf_note_t           *notes;
    uint32_t                   num_notes;
    n00b_elf_gnu_hash_t       *gnu_hash;
    n00b_elf_sysv_hash_t      *sysv_hash;
    n00b_elf_symbol_version_t *sym_versions;
    uint32_t                   num_sym_versions;
    n00b_elf_verneed_t        *verneed;
    n00b_elf_vernaux_t        *vernaux;
    uint32_t                   num_verneed;
    uint32_t                   num_vernaux;
    n00b_elf_verdef_t         *verdefs;
    uint32_t                   num_verdefs;
    n00b_string_t             *interpreter;
    n00b_buffer_t             *overlay;
    n00b_bstream_t             *stream;
    n00b_elf_core_info_t      *core_info;
} n00b_elf_binary_t;

// ============================================================================
// Parse API
// ============================================================================

/**
 * @brief Parse an ELF64 binary from a stream.
 *
 * The stream should be positioned at byte 0.  ELF magic and 64-bit class
 * are validated.  Endianness is detected from `e_ident[EI_DATA]`.
 *
 * @param stream  Binary stream to parse from.
 * @return Ok(binary) or Err(N00B_ERR_*).
 *
 * @kw allocator Optional allocator for parsed ELF data; default `nullptr`.
 */
extern n00b_result_t(n00b_elf_binary_t *)
n00b_elf_parse(n00b_bstream_t *stream) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

// ============================================================================
// Query API
// ============================================================================

/// Find a section by name; none if not found.
extern n00b_option_t(n00b_elf_section_t *)
    n00b_elf_section_by_name(n00b_elf_binary_t *bin, const char *name);

/// Find the first section with the given `sh_type`; none if not found.
extern n00b_option_t(n00b_elf_section_t *)
    n00b_elf_section_by_type(n00b_elf_binary_t *bin, uint32_t type);

/// Find the section containing `addr`; none if not found.
extern n00b_option_t(n00b_elf_section_t *)
    n00b_elf_section_at_addr(n00b_elf_binary_t *bin, uint64_t addr);

/// Find the first segment with the given `p_type`; none if not found.
extern n00b_option_t(n00b_elf_segment_t *)
    n00b_elf_segment_by_type(n00b_elf_binary_t *bin, uint32_t type);

/// Find the segment containing `vaddr`; none if not found.
extern n00b_option_t(n00b_elf_segment_t *)
    n00b_elf_segment_at_addr(n00b_elf_binary_t *bin, uint64_t vaddr);

/// Search symtab then dynsym for a symbol by name; none if not found.
extern n00b_option_t(n00b_elf_symbol_t *)
    n00b_elf_symbol_by_name(n00b_elf_binary_t *bin, const char *name);

/// Search only `.symtab` for a symbol by name; none if not found.
extern n00b_option_t(n00b_elf_symbol_t *)
    n00b_elf_symtab_by_name(n00b_elf_binary_t *bin, const char *name);

/// Search only `.dynsym` for a symbol by name; none if not found.
extern n00b_option_t(n00b_elf_symbol_t *)
    n00b_elf_dynsym_by_name(n00b_elf_binary_t *bin, const char *name);

/// Find the first dynamic entry with the given tag; none if not found.
extern n00b_option_t(n00b_elf_dynamic_t *)
    n00b_elf_dynamic_by_tag(n00b_elf_binary_t *bin, int64_t tag);

/// Find the first note with the given type; none if not found.
extern n00b_option_t(n00b_elf_note_t *)
    n00b_elf_note_by_type(n00b_elf_binary_t *bin, uint32_t type);

/// True if a section with the given name exists.
extern bool                 n00b_elf_has_section(n00b_elf_binary_t *bin,
                                                  const char *name);

/// True if a segment with the given type exists.
extern bool                 n00b_elf_has_segment(n00b_elf_binary_t *bin,
                                                  uint32_t type);

/// True if the binary has a PT_INTERP interpreter string.
extern bool                 n00b_elf_has_interpreter(n00b_elf_binary_t *bin);

/// True if this is a core dump (ET_CORE).
extern bool                 n00b_elf_is_core(n00b_elf_binary_t *bin);

/// Get the parsed core dump info; none if not a core dump.
extern n00b_option_t(n00b_elf_core_info_t *)
    n00b_elf_core_info(n00b_elf_binary_t *bin);

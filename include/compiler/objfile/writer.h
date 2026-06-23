/**
 * @file n00b_writer.h
 * @brief Binary writer with endian-aware access — inverse of `n00b_bstream_t`.
 *
 * Provides sequential writes with automatic buffer growth, random-access
 * patches (no cursor advance), alignment (zero-pad), and a helper for
 * building ELF/MachO string tables.
 */
#pragma once

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "compiler/objfile/types.h"

// ============================================================================
// Writer struct
// ============================================================================

/**
 * @brief Binary writer backed by an `n00b_buffer_t`.
 *
 * Writes are sequential (advancing `pos`) or random-access patches
 * (no cursor movement).  The buffer grows automatically when writes
 * exceed capacity.
 */
typedef struct n00b_writer {
    n00b_buffer_t *buf;          ///< Backing buffer (owned).
    size_t         pos;          ///< Current write position (byte offset).
    bool           swap_endian;  ///< Byte-swap multi-byte writes.
    bool           error;        ///< Set on allocation failure.
} n00b_writer_t;

// ============================================================================
// String table builder
// ============================================================================

/**
 * @brief Accumulates NUL-terminated strings for ELF/MachO string tables.
 *
 * The first byte is always NUL (empty string at offset 0).
 * Exact-match deduplication via linear scan.
 */
typedef struct n00b_strtab_builder {
    n00b_buffer_t *buf;   ///< Backing bytes; `n00b_buffer_len(buf)` is the
                          ///< logical table length (offset 0 = empty string).
} n00b_strtab_builder_t;

// ============================================================================
// Construction
// ============================================================================

/**
 * @brief Create a new writer with the given initial buffer capacity.
 *
 * The writer struct, its backing `n00b_buffer_t`, every growth performed by the
 * writer, and the buffer returned by ::n00b_writer_finalize are all allocated
 * from the `allocator` kwarg. Passing `allocator == nullptr` (the default) uses
 * the runtime default allocator. Supplying an explicit allocator lets a caller
 * obtain an arena-owned finalized buffer with no re-home copy (DF-007-01 /
 * NFR-05).
 *
 * @param initial_capacity  Starting buffer size in bytes.
 * @return A new writer; never nullptr.
 *
 * @kw allocator Allocator backing the writer and its output (nullptr = runtime
 *               default).
 *
 * @post The returned writer and its backing buffer are allocated from the
 *       `allocator` kwarg (or the runtime default when it is nullptr).
 */
extern n00b_writer_t *
n00b_writer_new(size_t initial_capacity) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

// ============================================================================
// Position
// ============================================================================

extern size_t n00b_writer_pos(n00b_writer_t *w);
extern void   n00b_writer_setpos(n00b_writer_t *w, size_t pos);

/**
 * @brief Advance position to the next multiple of @p alignment,
 *        zero-padding any gap.
 */
extern void   n00b_writer_align(n00b_writer_t *w, size_t alignment);

// ============================================================================
// Sequential writes (advance pos)
// ============================================================================

extern void n00b_writer_write_u8(n00b_writer_t *w, uint8_t v);
extern void n00b_writer_write_u16(n00b_writer_t *w, uint16_t v);
extern void n00b_writer_write_u32(n00b_writer_t *w, uint32_t v);
extern void n00b_writer_write_u64(n00b_writer_t *w, uint64_t v);

extern void n00b_writer_write_i8(n00b_writer_t *w, int8_t v);
extern void n00b_writer_write_i16(n00b_writer_t *w, int16_t v);
extern void n00b_writer_write_i32(n00b_writer_t *w, int32_t v);
extern void n00b_writer_write_i64(n00b_writer_t *w, int64_t v);

extern void n00b_writer_write_bytes(n00b_writer_t *w, const void *data,
                                     size_t n);
extern void n00b_writer_write_cstring(n00b_writer_t *w, const char *s);
extern void n00b_writer_write_buffer(n00b_writer_t *w, n00b_buffer_t *buf);
extern void n00b_writer_write_zeros(n00b_writer_t *w, size_t n);

extern void n00b_writer_write_uleb128(n00b_writer_t *w, uint64_t v);
extern void n00b_writer_write_sleb128(n00b_writer_t *w, int64_t v);

// ============================================================================
// Random-access patches (no cursor advance)
// ============================================================================

extern void n00b_writer_patch_u16(n00b_writer_t *w, size_t off, uint16_t v);
extern void n00b_writer_patch_u32(n00b_writer_t *w, size_t off, uint32_t v);
extern void n00b_writer_patch_u64(n00b_writer_t *w, size_t off, uint64_t v);
extern void n00b_writer_patch_i64(n00b_writer_t *w, size_t off, int64_t v);

// ============================================================================
// Endianness
// ============================================================================

extern void n00b_writer_set_endian(n00b_writer_t *w, n00b_endian_t endian);

// ============================================================================
// Error checking
// ============================================================================

/// Returns true if an allocation failure occurred during any write.
extern bool n00b_writer_has_error(n00b_writer_t *w);

// ============================================================================
// Finalize
// ============================================================================

/**
 * @brief Return the buffer truncated to the current position.
 *
 * The writer should not be used after this call.
 */
extern n00b_buffer_t *n00b_writer_finalize(n00b_writer_t *w);

// ============================================================================
// String table builder
// ============================================================================

/**
 * @brief Create a new (empty) string-table builder.
 *
 * The builder struct and its backing buffer (and every growth) are allocated
 * from the `allocator` kwarg; nullptr (the default) uses the runtime default.
 *
 * @kw allocator Allocator backing the builder and its bytes (nullptr = runtime
 *               default).
 */
extern n00b_strtab_builder_t *
n00b_strtab_builder_new() _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Add a string to the table, returning its byte offset.
 *
 * Deduplicates exact matches.  The empty string always lives at offset 0.
 */
extern uint32_t n00b_strtab_builder_add(n00b_strtab_builder_t *sb,
                                         const char *str);

/// Write the accumulated string table into a writer.
extern void n00b_strtab_builder_write(n00b_strtab_builder_t *sb,
                                       n00b_writer_t *w);

/// Current size of the string table in bytes.
extern size_t n00b_strtab_builder_size(n00b_strtab_builder_t *sb);

/**
 * @file n00b_stream.h
 * @brief Binary stream reader with endian-aware access.
 *
 * Wraps an `n00b_buffer_t *` with position tracking, bounds checking,
 * and byte-swap support for multi-byte reads.
 */
#pragma once

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "adt/result.h"
#include "adt/option.h"
#include "core/string.h"
#include "compiler/objfile/types.h"

// ============================================================================
// Stream struct
// ============================================================================

/**
 * @brief Binary stream reader backed by an `n00b_buffer_t`.
 *
 * Provides sequential and random-access reads with automatic endian
 * conversion.  All read/peek operations return `n00b_result_t` for
 * bounds-safe access.
 */
struct n00b_stream {
    n00b_buffer_t    *buf;         ///< Backing buffer.
    size_t            pos;         ///< Current read position (byte offset).
    n00b_allocator_t *allocator;   ///< Allocator for stream-owned results.
    bool              swap_endian; ///< Byte-swap multi-byte reads.
};

// ============================================================================
// Construction
// ============================================================================

/**
 * @brief Create a stream wrapping an existing buffer.
 * @param buf  Buffer to read from (caller retains ownership).
 * @return     Heap-allocated stream, or nullptr if buf is nullptr.
 *
 * @kw allocator Allocator for the stream wrapper and copied read results;
 *               default `nullptr`.
 */
extern n00b_bstream_t *n00b_bstream_new(n00b_buffer_t *buf) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Create a stream by reading a file into memory.
 * @param path  Filesystem path.
 * @return      Ok(stream) or Err(errno / N00B_ERR_READ).
 *
 * @kw allocator Allocator for the file buffer, stream wrapper, and copied
 *               read results; default `nullptr`.
 */
extern n00b_result_t(n00b_bstream_t *)
n00b_bstream_from_file(const char *path) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

// ============================================================================
// Position
// ============================================================================

extern size_t                 n00b_bstream_pos(n00b_bstream_t *s);
extern n00b_result_t(bool)    n00b_bstream_setpos(n00b_bstream_t *s, size_t pos);
extern n00b_result_t(bool)    n00b_bstream_advance(n00b_bstream_t *s, size_t n);
extern size_t                 n00b_bstream_remaining(n00b_bstream_t *s);
extern bool                   n00b_bstream_can_read(n00b_bstream_t *s, size_t n);
extern n00b_result_t(bool)    n00b_bstream_align(n00b_bstream_t *s, size_t alignment);

// ============================================================================
// Read (at current pos, advances)
// ============================================================================

extern n00b_result_t(uint8_t)  n00b_bstream_read_u8(n00b_bstream_t *s);
extern n00b_result_t(uint16_t) n00b_bstream_read_u16(n00b_bstream_t *s);
extern n00b_result_t(uint32_t) n00b_bstream_read_u32(n00b_bstream_t *s);
extern n00b_result_t(uint64_t) n00b_bstream_read_u64(n00b_bstream_t *s);

extern n00b_result_t(int8_t)   n00b_bstream_read_i8(n00b_bstream_t *s);
extern n00b_result_t(int16_t)  n00b_bstream_read_i16(n00b_bstream_t *s);
extern n00b_result_t(int32_t)  n00b_bstream_read_i32(n00b_bstream_t *s);
extern n00b_result_t(int64_t)  n00b_bstream_read_i64(n00b_bstream_t *s);

extern n00b_result_t(n00b_buffer_t *) n00b_bstream_read_bytes(n00b_bstream_t *s,
                                                              size_t n);

extern n00b_result_t(n00b_string_t *)  n00b_bstream_read_cstring(n00b_bstream_t *s);

extern n00b_result_t(uint64_t) n00b_bstream_read_uleb128(n00b_bstream_t *s);
extern n00b_result_t(int64_t)  n00b_bstream_read_sleb128(n00b_bstream_t *s);

// ============================================================================
// Peek (at offset, no advance)
// ============================================================================

extern n00b_result_t(uint8_t)  n00b_bstream_peek_u8(n00b_bstream_t *s, size_t offset);
extern n00b_result_t(uint16_t) n00b_bstream_peek_u16(n00b_bstream_t *s, size_t offset);
extern n00b_result_t(uint32_t) n00b_bstream_peek_u32(n00b_bstream_t *s, size_t offset);
extern n00b_result_t(uint64_t) n00b_bstream_peek_u64(n00b_bstream_t *s, size_t offset);

extern n00b_result_t(n00b_buffer_t *) n00b_bstream_peek_bytes(n00b_bstream_t *s,
                                                              size_t offset,
                                                              size_t n);
extern n00b_result_t(n00b_string_t *)  n00b_bstream_peek_cstring(n00b_bstream_t *s,
                                                                size_t offset);

// ============================================================================
// Raw access
// ============================================================================

/**
 * @brief Pointer to raw bytes at the current position.
 * @pre Stream must have at least 1 byte remaining.
 */
extern const uint8_t *n00b_bstream_raw(n00b_bstream_t *s);

/**
 * @brief Pointer to raw bytes at an absolute offset.
 * @return Ok(ptr) or Err(N00B_ERR_OUT_OF_BOUNDS).
 */
extern n00b_result_t(const uint8_t *) n00b_bstream_raw_at(n00b_bstream_t *s,
                                                          size_t offset);

// ============================================================================
// Endianness
// ============================================================================

extern void n00b_bstream_set_endian(n00b_bstream_t *s, n00b_endian_t endian);

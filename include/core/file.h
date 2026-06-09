/**
 * @file file.h
 * @brief Unified file API over conduit-stream + mmap substrates.
 *
 * One read/write/seek surface for both event-driven streaming I/O
 * (conduit `fd_owner` underneath) and random-access mmap'd buffers
 * (`core/file_map.h` underneath). Callers pick the substrate at open
 * time; everything afterwards is uniform.
 *
 *  - `N00B_FILE_KIND_STREAM`: forward-only, suited to hashes, scans,
 *    and any sequential consumer. Memory profile bounded by the
 *    conduit accumulator's chunk size, regardless of file size.
 *  - `N00B_FILE_KIND_MMAP`: full random access, zero-copy slicing
 *    via `n00b_file_as_buffer()`. Resident set ≈ pages actually
 *    touched (kernel demand-pages).
 *  - `N00B_FILE_KIND_AUTO`: regular files → MMAP (read-only) or
 *    STREAM (writable); pipes/sockets/devices → STREAM.
 *
 * Read semantics: `n00b_file_read(f, max_n)` returns up to `max_n`
 * bytes, possibly fewer (short read or near-EOF). Returns a zero-byte
 * buffer at EOF; subsequent calls remain at EOF.
 *
 * Seek semantics: STREAM supports forward-only seeks (negative or
 * absolute-into-past returns `EINVAL`); MMAP supports full seeking
 * including SEEK_END. The substrate kind is queryable via
 * `n00b_file_get_kind` for callers that need to know.
 *
 * Async-read semantics: STREAM forwards to `n00b_conduit_read_async`
 * when the stream is conduit-managed; fd-backed regular STREAM files
 * and MMAP perform the read synchronously and push the result to the
 * caller's inbox before returning (the "async contract" is the inbox
 * delivery, not deferred work).
 */
#pragma once

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "conduit/conduit.h"
#include "conduit/fd_managed.h"
#include "conduit/rw.h"

#ifndef _WIN32
#include <stdio.h>  /* SEEK_SET / SEEK_CUR / SEEK_END */
#endif

// Forward declaration — struct definition lives in src/core/file.c.
#ifndef N00B_FILE_T_DECLARED
#define N00B_FILE_T_DECLARED
typedef struct n00b_file n00b_file_t;
#endif

// ============================================================================
// Substrate
// ============================================================================

typedef enum {
    /** Pick STREAM for non-regular files and writable opens, MMAP for
     *  read-only opens of regular files. */
    N00B_FILE_KIND_AUTO,
    /** Event-driven stream over a conduit-managed FD. */
    N00B_FILE_KIND_STREAM,
    /** Random-access mmap of the entire file. */
    N00B_FILE_KIND_MMAP,
} n00b_file_kind_t;

// ============================================================================
// Mode flags (bitmask)
// ============================================================================

typedef enum {
    N00B_FILE_READ     = 1 << 0,
    N00B_FILE_WRITE    = 1 << 1,
    N00B_FILE_CREATE   = 1 << 2,
    N00B_FILE_TRUNCATE = 1 << 3,
    N00B_FILE_APPEND   = 1 << 4,
} n00b_file_mode_flag_t;

#define N00B_FILE_R  (N00B_FILE_READ)
#define N00B_FILE_W  (N00B_FILE_WRITE | N00B_FILE_CREATE | N00B_FILE_TRUNCATE)
#define N00B_FILE_RW (N00B_FILE_READ | N00B_FILE_WRITE | N00B_FILE_CREATE)

typedef enum : int32_t {
    N00B_FILE_OK = 0,
    N00B_FILE_ERR_ARG = -1,
    N00B_FILE_ERR_IO = -2,
    N00B_FILE_ERR_NOT_FOUND = -3,
    N00B_FILE_ERR_PERMISSION = -4,
    N00B_FILE_ERR_NOT_SUPPORTED = -5,
    N00B_FILE_ERR_NO_SPACE = -6,
    N00B_FILE_ERR_IS_DIR = -7,
    N00B_FILE_ERR_NOT_DIR = -8,
    N00B_FILE_ERR_EXISTS = -9,
} n00b_file_err_t;

/** @brief Static diagnostic string for a @c N00B_FILE_* error code. */
extern n00b_string_t *n00b_file_err_str(n00b_err_t err);

/**
 * @brief Completion facts for a single file write attempt.
 *
 * When @c error is true, @c bytes_written is the number of bytes accepted
 * before the error became observable and @c error_code is the same error
 * domain reported by @ref n00b_file_write.
 */
typedef struct {
    size_t bytes_written;
    bool   error;
    int    error_code;
} n00b_file_write_attempt_t;

// ============================================================================
// Open / close
// ============================================================================

/**
 * @brief Open a file.
 *
 * @param path  NUL-terminated path (the n00b_string_t's `data` field
 *              is treated as a C string).
 *
 * @kw mode      Bitmask of `N00B_FILE_*` flags. Default: read-only.
 * @kw kind      Substrate to use. Default: AUTO.
 * @kw populate  MMAP only: pass `MAP_POPULATE` so pages are
 *               pre-faulted (Linux). Default: false. Ignored for
 *               STREAM and on non-Linux.
 *
 * @return Ok(file) on success, Err(errno) on `open`/`fstat`/`mmap`
 * failure, Err(`ENOSYS`) if MMAP requested but not supported on this
 * platform (Windows), or Err(`EINVAL`) on inconsistent args.
 */
extern n00b_result_t(n00b_file_t *)
n00b_file_open(n00b_string_t *path) _kargs
{
    uint32_t         mode     = N00B_FILE_R;
    n00b_file_kind_t kind     = N00B_FILE_KIND_AUTO;
    bool             populate = false;
};

/**
 * @brief Create a new stream file and fail if the path already exists.
 *
 * Uses the host exclusive-create primitive (`O_CREAT | O_EXCL` on POSIX)
 * and returns `Err(EEXIST)` without opening or truncating an existing path.
 *
 * @param path Path to create.
 *
 * @kw file_mode Requested create mode bits (default: `0600`; subject to
 *               host create-mode behavior such as umask).
 * @kw allocator Allocator for the returned file handle.
 *
 * @return Ok(file) on success, Err(errno) on open/manage failure.
 */
extern n00b_result_t(n00b_file_t *)
n00b_file_open_exclusive(n00b_string_t *path) _kargs
{
    uint32_t          file_mode = 0600;
    n00b_allocator_t *allocator = nullptr;
};

/** @brief Close the file and release substrate resources. Safe on null. */
extern void n00b_file_close(n00b_file_t *f);

/**
 * @brief Flush and close the file, reporting pre-close or close errors.
 *
 * Writable stream files are flushed before teardown where the host supports
 * doing so. The handle is released even when an error is reported, so callers
 * should not reuse @p f after this call.
 *
 * @param f File handle to close. May be null.
 *
 * @return `Ok(true)` when a non-null handle closed without observed error,
 *         `Ok(false)` when @p f was null, or `Err(errno)` for the first
 *         observed flush/close failure.
 */
extern n00b_result_t(bool)
n00b_file_close_result(n00b_file_t *f);

/**
 * @brief Durably sync the file or directory at @p path where supported.
 *
 * This is the host-file substrate primitive for callers that need a durable
 * path-level visibility barrier outside an open @ref n00b_file_t handle.
 *
 * @param path NUL-terminated path stored in an @c n00b_string_t.
 * @return Ok(true) on success, or Err(N00B_FILE_ERR_*) for argument,
 *         durability, permission, missing-path, or unsupported-platform
 *         failures.
 */
extern n00b_result_t(bool)
n00b_file_sync_path(n00b_string_t *path);

// ============================================================================
// Read / write / seek
// ============================================================================

/**
 * @brief Read up to `max_n` bytes.
 *
 * STREAM: blocks until at least one byte arrives or EOF/error;
 * returns whatever the conduit handed back (possibly less than
 * `max_n`).
 *
 * MMAP: returns a slice of the underlying buffer at the current
 * position with length `min(max_n, remaining)`; advances `pos`. The
 * returned buffer is a fresh `n00b_buffer_t` wrapping the same bytes
 * (no copy) — its lifetime is tied to the parent mmap'd buffer.
 *
 * Both: returns a zero-byte buffer at EOF. Caller may loop until
 * `n00b_file_at_eof(f)` returns true.
 *
 * @return Ok(chunk) on success (chunk may be empty), Err(errno) on
 * I/O failure.
 */
extern n00b_result_t(n00b_buffer_t *) n00b_file_read(n00b_file_t *f, size_t max_n);

/**
 * @brief Write `n` bytes from `p`.
 *
 * STREAM: blocks until the conduit's write queue acknowledges
 * completion. Returns the bytes-written count from the kernel.
 *
 * MMAP (writable only): memcpys into the mapping at the current
 * position, advances `pos`, returns `n`. `EROFS` for read-only mmap.
 *
 * @return Ok(bytes_written) or Err(errno).
 */
extern n00b_result_t(size_t)
n00b_file_write(n00b_file_t *f, const void *p, size_t n);

/**
 * @brief Write bytes once and preserve partial-completion facts on error.
 *
 * This is the fact-preserving form of @ref n00b_file_write. It returns
 * `Ok(attempt)` for an observed write completion, even when the write
 * completion includes an error after partial progress. Invalid arguments or
 * failures before completion facts are available return `Err(errno/code)`.
 *
 * @param f Writable file handle.
 * @param p Bytes to write.
 * @param n Number of bytes to write.
 *
 * @return `Ok(attempt)` with byte/error facts, or `Err(errno/code)` when the
 *         write could not be attempted.
 */
extern n00b_result_t(n00b_file_write_attempt_t)
n00b_file_write_attempt(n00b_file_t *f, const void *p, size_t n);

/**
 * @brief Write an entire buffer, looping over short writes.
 *
 * @param f      Writable file handle.
 * @param buffer Buffer whose bytes should be written. For zero-length
 *               buffers, `buffer->data` may be `nullptr`.
 *
 * @return Ok(total bytes written), or the first error returned by the
 *         underlying write operation. Callers that need the partial byte count
 *         associated with an error should use @ref n00b_file_write_attempt.
 */
extern n00b_result_t(size_t)
n00b_file_write_all(n00b_file_t *f, n00b_buffer_t *buffer);

/**
 * @brief Apply mode bits to an open file and report observed bits.
 *
 * @param f    Open file handle.
 * @param mode Requested low twelve POSIX mode bits.
 *
 * @return `Ok(mode)` with observed low twelve mode bits after application.
 *         `Err(ENOSYS)` on hosts without mode support, or `Err(errno)` on
 *         failure.
 */
extern n00b_result_t(uint32_t)
n00b_file_apply_mode(n00b_file_t *f, uint32_t mode);

/**
 * @brief Move the read/write position.
 *
 * STREAM: forward-only. Absolute or `SEEK_CUR`-with-positive-offset
 * targets are honored by discarding bytes; backward seeks and
 * `SEEK_END` return `EINVAL`.
 *
 * MMAP: full random access including SEEK_END.
 *
 * @return Ok(new_pos) or Err(errno).
 */
extern n00b_result_t(int64_t)
n00b_file_seek(n00b_file_t *f, int64_t off, int whence);

/** @brief Current position. */
extern int64_t n00b_file_tell(n00b_file_t *f);

/** @brief File size in bytes, or -1 if unknown (STREAM over a pipe). */
extern int64_t n00b_file_size(n00b_file_t *f);

/** @brief True iff the next `read` is guaranteed to return 0 bytes. */
extern bool n00b_file_at_eof(n00b_file_t *f);

/** @brief Substrate currently in use (AUTO resolves at open time). */
extern n00b_file_kind_t n00b_file_get_kind(n00b_file_t *f);

// ============================================================================
// MMAP escape hatch
// ============================================================================

/**
 * @brief Get the underlying mmap'd buffer (MMAP substrate only).
 *
 * Useful for parsers that want to bstream the whole file with full
 * random access. The buffer is the *whole* mapping — independent of
 * the file's current `pos`. Returned buffer aliases the mapping;
 * lifetime tied to the file (or until the buffer is reachable via GC).
 *
 * @return Ok(buf) on MMAP, Err(`ENOTSUP`) on STREAM.
 */
extern n00b_result_t(n00b_buffer_t *) n00b_file_as_buffer(n00b_file_t *f);

// ============================================================================
// Async read
// ============================================================================

/**
 * @brief Subscribe-style read.
 *
 * STREAM: forwards to `n00b_conduit_read_async` on the FD's
 * read_topic when the file has a conduit-managed read topic; fd-backed
 * regular STREAM files synchronously read up to `max_n` bytes and
 * push the result to `inbox`, returning Ok({inbox, INVALID_HANDLE}).
 *
 * MMAP: synchronously reads up to `max_n` bytes (as for
 * `n00b_file_read`), pushes a message carrying the buffer to
 * `inbox`, returns Ok({inbox, INVALID_HANDLE}). The handle is
 * `N00B_CONDUIT_INVALID_SUB_HANDLE` because no real subscription
 * exists; `n00b_conduit_sub_cancel` on the invalid handle is a
 * documented no-op.
 *
 * In both cases the caller drains the inbox via the usual pop /
 * condition_wait loop and treats the returned handle uniformly
 * (cancel is safe).
 *
 * @return Ok({inbox, handle}) or Err(errno).
 */
extern n00b_result_t(n00b_conduit_async_read_t(n00b_buffer_t *))
n00b_file_read_async(n00b_file_t                           *f,
                     size_t                                 max_n,
                     n00b_conduit_inbox_t(n00b_buffer_t *) *inbox);

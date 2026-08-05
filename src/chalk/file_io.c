/** @file src/chalk/file_io.c — file I/O for chalk codec file-mode
 *        entry points.
 *
 *  Built on top of n00b's unified file API (`core/file.h`). Read paths
 *  go through MMAP (zero-copy access for parser-backed codecs);
 *  write/delete paths are plain `n00b_file_open` + `n00b_file_write`
 *  + `unlink(2)`. The streaming-SHA-256 helper uses the STREAM
 *  substrate with a 64 KiB chunk loop.
 *
 *  Sidecar codecs use a fixed ".chalk" suffix (matching the chalk-tool
 *  default). */

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/alloc.h"
#include "core/sha256.h"
#include "core/file.h"
#include "chalk/n00b_chalk.h"
#include "internal/chalk/file_io.h"

#include <errno.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif

static n00b_string_t *
sidecar_path(n00b_string_t *path)
{
    size_t plen = path->u8_bytes;
    char  *buf  = n00b_alloc_array(char, plen + 6 + 1);
    memcpy(buf, path->data, plen);
    memcpy(buf + plen, ".chalk", 6);
    buf[plen + 6] = '\0';
    return n00b_string_from_raw(buf, (int64_t)(plen + 6));
}

// -----------------------------------------------------------------------
// Path-based read / write
// -----------------------------------------------------------------------

n00b_result_t(n00b_buffer_t *)
n00b_chalk_read_file(n00b_string_t *path)
{
    if (!path) return n00b_result_err(n00b_buffer_t *, EINVAL);
    auto fr = n00b_file_open(path, .kind = N00B_FILE_KIND_MMAP);
    if (n00b_result_is_err(fr)) {
        return n00b_result_err(n00b_buffer_t *, n00b_result_get_err(fr));
    }
    n00b_file_t *f = n00b_result_get(fr);
    auto br = n00b_file_as_buffer(f);
    n00b_file_close(f);
    if (n00b_result_is_err(br)) {
        return n00b_result_err(n00b_buffer_t *, n00b_result_get_err(br));
    }
    n00b_buffer_t *mapped = n00b_result_get(br);
#ifdef _WIN32
    // Windows keeps mapped views coupled to the underlying path strongly
    // enough to block the truncate/write step used by file-mode chalking.
    // Return ordinary owned bytes so callers can rewrite the same file.
    n00b_buffer_t *copy =
        n00b_buffer_from_bytes(mapped->data, (int64_t)mapped->byte_len);
    n00b_buffer_free(mapped);
    return n00b_result_ok(n00b_buffer_t *, copy);
#else
    return n00b_result_ok(n00b_buffer_t *, mapped);
#endif
}

n00b_result_t(bool)
n00b_chalk_write_file(n00b_string_t *path, n00b_buffer_t *bytes)
{
    if (!path || !bytes) return n00b_result_err(bool, EINVAL);
    auto fr = n00b_file_open(path, .mode = N00B_FILE_W,
                                    .kind = N00B_FILE_KIND_STREAM);
    if (n00b_result_is_err(fr)) {
        return n00b_result_err(bool, n00b_result_get_err(fr));
    }
    n00b_file_t *f = n00b_result_get(fr);
    auto wr = n00b_file_write(f, bytes->data, bytes->byte_len);
    n00b_file_close(f);
    if (n00b_result_is_err(wr)) {
        return n00b_result_err(bool, n00b_result_get_err(wr));
    }
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_buffer_t *)
n00b_chalk_read_sidecar(n00b_string_t *path)
{
    return n00b_chalk_read_file(sidecar_path(path));
}

n00b_result_t(bool)
n00b_chalk_write_sidecar(n00b_string_t *path, n00b_buffer_t *bytes)
{
    return n00b_chalk_write_file(sidecar_path(path), bytes);
}

n00b_result_t(bool)
n00b_chalk_delete_sidecar(n00b_string_t *path)
{
    if (!path) return n00b_result_err(bool, EINVAL);
#ifdef _WIN32
    return n00b_result_err(bool, ENOSYS);
#else
    n00b_string_t *sp = sidecar_path(path);
    if (unlink((const char *)sp->data) != 0) {
        return n00b_result_err(bool, errno);
    }
    return n00b_result_ok(bool, true);
#endif
}

// -----------------------------------------------------------------------
// Compose: buffer-mode → file-mode
// -----------------------------------------------------------------------

static n00b_result_t(bool)
write_io_result(n00b_string_t *path, n00b_chalk_io_result_t *io)
{
    if (io->kind == N00B_CHALK_OUT_SIDECAR) {
        if (io->bytes->byte_len == 0) {
            return n00b_chalk_delete_sidecar(path);
        }
        return n00b_chalk_write_sidecar(path, io->bytes);
    }
    return n00b_chalk_write_file(path, io->bytes);
}

n00b_result_t(n00b_chalk_io_result_t *)
n00b_chalk_file_insert_via(n00b_string_t        *path,
                           n00b_chalk_mark_t    *mark,
                           n00b_chalk_buf_io_fn_t buf_insert)
{
    auto rr = n00b_chalk_read_file(path);
    if (n00b_result_is_err(rr)) {
        return n00b_result_err(n00b_chalk_io_result_t *, 1);
    }
    auto ir = buf_insert(n00b_result_get(rr), mark);
    if (n00b_result_is_err(ir)) {
        return n00b_result_err(n00b_chalk_io_result_t *, 2);
    }
    n00b_chalk_io_result_t *io = n00b_result_get(ir);
    auto wr = write_io_result(path, io);
    if (n00b_result_is_err(wr)) {
        return n00b_result_err(n00b_chalk_io_result_t *, 3);
    }
    return n00b_result_ok(n00b_chalk_io_result_t *, io);
}

n00b_result_t(n00b_chalk_io_result_t *)
n00b_chalk_file_delete_via(n00b_string_t            *path,
                           n00b_chalk_buf_io_unary_t buf_delete)
{
    auto rr = n00b_chalk_read_file(path);
    if (n00b_result_is_err(rr)) {
        return n00b_result_err(n00b_chalk_io_result_t *, 1);
    }
    auto ir = buf_delete(n00b_result_get(rr));
    if (n00b_result_is_err(ir)) {
        return n00b_result_err(n00b_chalk_io_result_t *, 2);
    }
    n00b_chalk_io_result_t *io = n00b_result_get(ir);
    auto wr = write_io_result(path, io);
    if (n00b_result_is_err(wr)) {
        return n00b_result_err(n00b_chalk_io_result_t *, 3);
    }
    return n00b_result_ok(n00b_chalk_io_result_t *, io);
}

n00b_result_t(n00b_chalk_extract_result_t *)
n00b_chalk_file_extract_via(n00b_string_t              *path,
                            n00b_chalk_buf_extract_fn_t buf_extract)
{
    auto rr = n00b_chalk_read_file(path);
    if (n00b_result_is_err(rr)) {
        return n00b_result_err(n00b_chalk_extract_result_t *, 1);
    }
    return buf_extract(n00b_result_get(rr));
}

n00b_result_t(n00b_buffer_t *)
n00b_chalk_file_hash_via(n00b_string_t            *path,
                         n00b_chalk_buf_hash_fn_t  buf_hash)
{
    auto rr = n00b_chalk_read_file(path);
    if (n00b_result_is_err(rr)) return n00b_result_err(n00b_buffer_t *, 1);
    return buf_hash(n00b_result_get(rr));
}

// -----------------------------------------------------------------------
// Streaming SHA-256 of a file via the STREAM substrate.
//
// Memory profile: resident set is bounded by one conduit chunk
// (kernel hands back whatever it has, typically a small page-aligned
// amount). A 50 GB file hashes with ~kilobytes resident.
// -----------------------------------------------------------------------

n00b_result_t(n00b_buffer_t *)
n00b_chalk_hash_file_stream(n00b_string_t *path)
{
    if (!path) return n00b_result_err(n00b_buffer_t *, EINVAL);
    auto fr = n00b_file_open(path, .kind = N00B_FILE_KIND_STREAM);
    if (n00b_result_is_err(fr)) {
        return n00b_result_err(n00b_buffer_t *, n00b_result_get_err(fr));
    }
    n00b_file_t *f = n00b_result_get(fr);

    n00b_sha256_ctx_t ctx;
    n00b_sha256_init(&ctx);

    while (!n00b_file_at_eof(f)) {
        auto rr = n00b_file_read(f, 65536);
        if (n00b_result_is_err(rr)) {
            n00b_file_close(f);
            return n00b_result_err(n00b_buffer_t *,
                                   n00b_result_get_err(rr));
        }
        n00b_buffer_t *chunk = n00b_result_get(rr);
        if (!chunk || chunk->byte_len == 0) break;
        n00b_sha256_update(&ctx, chunk->data, chunk->byte_len);
    }
    n00b_file_close(f);

    n00b_sha256_digest_t words;
    n00b_sha256_finalize(&ctx, words);
    uint8_t bytes[32];
    for (int i = 0; i < 8; i++) {
        uint32_t w       = words[i];
        bytes[i * 4]     = (uint8_t)((w >> 24) & 0xff);
        bytes[i * 4 + 1] = (uint8_t)((w >> 16) & 0xff);
        bytes[i * 4 + 2] = (uint8_t)((w >> 8) & 0xff);
        bytes[i * 4 + 3] = (uint8_t)(w & 0xff);
    }
    return n00b_result_ok(n00b_buffer_t *,
                          n00b_buffer_from_bytes((char *)bytes, 32));
}

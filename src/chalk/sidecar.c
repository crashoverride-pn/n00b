/** @file src/chalk/sidecar.c — sidecar codec.
 *
 *  For artifact kinds that can't be marked in-band (ML model weights,
 *  X.509 certs, anything else this codec is asked to handle), libchalk
 *  emits the chalk mark as a sibling file `<artifact>.chalk`.
 *
 *  All four operations flow through chalk_io_result_t /
 *  chalk_extract_result_t with kind/source = SIDECAR — the caller
 *  never has the sidecar written silently to disk in buffer mode.
 *
 *  Cert support reuses the same implementation; the only difference is
 *  the codec id recorded in extract_result.codec. See certs.c. */

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/sha256.h"
#include "core/alloc.h"
#include "parsers/json.h"
#include "adt/dict.h"
#include "chalk/n00b_chalk.h"
#include "internal/chalk/mark_internal.h"
#include "internal/chalk/sidecar_internal.h"

#include <string.h>

// -----------------------------------------------------------------------
// Shared helpers (used by certs.c too)
// -----------------------------------------------------------------------

n00b_buffer_t *
n00b_chalk_sha256_buffer(n00b_buffer_t *in)
{
    n00b_sha256_digest_t words;
    n00b_sha256_hash(in->data, in->byte_len, words);
    uint8_t bytes[32];
    for (int i = 0; i < 8; i++) {
        uint32_t w = words[i];
        bytes[i * 4]     = (uint8_t)((w >> 24) & 0xff);
        bytes[i * 4 + 1] = (uint8_t)((w >> 16) & 0xff);
        bytes[i * 4 + 2] = (uint8_t)((w >> 8) & 0xff);
        bytes[i * 4 + 3] = (uint8_t)(w & 0xff);
    }
    return n00b_buffer_from_bytes((char *)bytes, 32);
}

// Convert a parsed JSON OBJECT into the typed mark dict. Identical to
// the pyc.c helper; will be deduped into mark.c later.
n00b_dict_t(n00b_string_t *, n00b_json_node_t *) *
n00b_chalk_json_object_to_dict(n00b_json_node_t *root)
{
    auto d = (n00b_dict_t(n00b_string_t *, n00b_json_node_t *) *)
                 n00b_alloc(n00b_dict_t(n00b_string_t *, n00b_json_node_t *));
    n00b_dict_init(d);
    n00b_json_object_t *obj = n00b_json_as_object(root);
    if (obj == nullptr) return d;
    n00b_dict_foreach(obj, key, value, {
        n00b_dict_put(d, key, value);
    });
    return d;
}

// -----------------------------------------------------------------------
// Codec-agnostic sidecar implementation (shared with certs.c)
// -----------------------------------------------------------------------

n00b_result_t(n00b_chalk_io_result_t *)
n00b_chalk_sidecar_insert_impl(n00b_buffer_t *bytes, n00b_chalk_mark_t *mark)
{
    if (!bytes || !mark) {
        return n00b_result_err(n00b_chalk_io_result_t *, 1);
    }
    auto hash_buf = n00b_chalk_sha256_buffer(bytes);
    auto fin      = n00b_chalk_mark_finalize(mark, hash_buf);
    if (n00b_result_is_err(fin)) {
        return n00b_result_err(n00b_chalk_io_result_t *, 2);
    }
    auto r = (n00b_chalk_io_result_t *)n00b_alloc(n00b_chalk_io_result_t);
    r->kind           = N00B_CHALK_OUT_SIDECAR;
    r->bytes          = n00b_result_get(fin);
    r->sidecar_suffix = r".chalk";
    return n00b_result_ok(n00b_chalk_io_result_t *, r);
}

n00b_result_t(n00b_chalk_io_result_t *)
n00b_chalk_sidecar_delete_impl(n00b_buffer_t *bytes)
{
    if (!bytes) return n00b_result_err(n00b_chalk_io_result_t *, 1);
    auto r = (n00b_chalk_io_result_t *)n00b_alloc(n00b_chalk_io_result_t);
    r->kind           = N00B_CHALK_OUT_SIDECAR;
    r->bytes          = n00b_buffer_from_bytes("", 0);
    r->sidecar_suffix = r".chalk";
    return n00b_result_ok(n00b_chalk_io_result_t *, r);
}

n00b_result_t(n00b_buffer_t *)
n00b_chalk_sidecar_hash_impl(n00b_buffer_t *bytes)
{
    if (!bytes) return n00b_result_err(n00b_buffer_t *, 1);
    return n00b_result_ok(n00b_buffer_t *, n00b_chalk_sha256_buffer(bytes));
}

n00b_result_t(n00b_chalk_extract_result_t *)
n00b_chalk_sidecar_parse_bytes(n00b_buffer_t       *sidecar_bytes,
                               n00b_chalk_codec_id_t codec)
{
    if (!sidecar_bytes) {
        return n00b_result_err(n00b_chalk_extract_result_t *, 1);
    }
    const char       *err  = nullptr;
    n00b_json_node_t *root = n00b_json_parse(sidecar_bytes->data,
                                             sidecar_bytes->byte_len,
                                             &err);
    if (!n00b_json_is_object(root)) {
        return n00b_result_err(n00b_chalk_extract_result_t *, 2);
    }
    auto r = (n00b_chalk_extract_result_t *)
                 n00b_alloc(n00b_chalk_extract_result_t);
    r->codec  = codec;
    r->source = N00B_CHALK_OUT_SIDECAR;
    r->mark   = n00b_chalk_json_object_to_dict(root);
    return n00b_result_ok(n00b_chalk_extract_result_t *, r);
}

// -----------------------------------------------------------------------
// n00b_chalk_sidecar_* — model sidecar
// -----------------------------------------------------------------------

n00b_result_t(n00b_chalk_io_result_t *)
n00b_chalk_sidecar_insert_buffer(n00b_buffer_t *bytes, n00b_chalk_mark_t *mark)
{
    return n00b_chalk_sidecar_insert_impl(bytes, mark);
}

n00b_result_t(n00b_chalk_io_result_t *)
n00b_chalk_sidecar_delete_buffer(n00b_buffer_t *bytes)
{
    return n00b_chalk_sidecar_delete_impl(bytes);
}

n00b_result_t(n00b_chalk_extract_result_t *)
n00b_chalk_sidecar_extract_buffer(n00b_buffer_t *bytes)
{
    (void)bytes;
    return n00b_result_err(n00b_chalk_extract_result_t *, 1);
}

n00b_result_t(n00b_buffer_t *)
n00b_chalk_sidecar_hash_buffer(n00b_buffer_t *bytes)
{
    return n00b_chalk_sidecar_hash_impl(bytes);
}

n00b_result_t(n00b_chalk_extract_result_t *)
n00b_chalk_sidecar_extract_sidecar_buffer(n00b_buffer_t *sidecar_bytes)
{
    return n00b_chalk_sidecar_parse_bytes(sidecar_bytes,
                                          N00B_CHALK_CODEC_SIDECAR_MODEL);
}

#include "internal/chalk/file_io.h"

// Streaming insert: we only need the artifact's unchalked SHA-256
// to finalize CHALK_ID — the artifact bytes themselves don't go
// into the sidecar. Stream-hash the file, finalize, write sidecar.
// Peak resident: one chunk + the mark JSON. No artifact in RAM.
n00b_result_t(n00b_chalk_io_result_t *)
n00b_chalk_sidecar_insert_file(n00b_string_t *path, n00b_chalk_mark_t *mark)
{
    if (!path || !mark) return n00b_result_err(n00b_chalk_io_result_t *, 1);
    auto hr = n00b_chalk_hash_file_stream(path);
    if (n00b_result_is_err(hr)) {
        return n00b_result_err(n00b_chalk_io_result_t *, 2);
    }
    n00b_buffer_t *hash_buf = n00b_result_get(hr);
    auto fin = n00b_chalk_mark_finalize(mark, hash_buf);
    if (n00b_result_is_err(fin)) {
        return n00b_result_err(n00b_chalk_io_result_t *, 3);
    }
    n00b_buffer_t *encoded = n00b_result_get(fin);
    auto wr = n00b_chalk_write_sidecar(path, encoded);
    if (n00b_result_is_err(wr)) {
        return n00b_result_err(n00b_chalk_io_result_t *, 4);
    }
    auto r = (n00b_chalk_io_result_t *)n00b_alloc(n00b_chalk_io_result_t);
    r->kind           = N00B_CHALK_OUT_SIDECAR;
    r->bytes          = encoded;
    r->sidecar_suffix = r".chalk";
    return n00b_result_ok(n00b_chalk_io_result_t *, r);
}

// Streaming delete: we only need to remove the sidecar — the
// artifact bytes are irrelevant. No file read at all.
n00b_result_t(n00b_chalk_io_result_t *)
n00b_chalk_sidecar_delete_file(n00b_string_t *path)
{
    if (!path) return n00b_result_err(n00b_chalk_io_result_t *, 1);
    auto dr = n00b_chalk_delete_sidecar(path);
    if (n00b_result_is_err(dr)) {
        // Treat "sidecar absent" as success — nothing to do.
        auto r = (n00b_chalk_io_result_t *)n00b_alloc(n00b_chalk_io_result_t);
        r->kind           = N00B_CHALK_OUT_SIDECAR;
        r->bytes          = n00b_buffer_from_bytes("", 0);
        r->sidecar_suffix = r".chalk";
        return n00b_result_ok(n00b_chalk_io_result_t *, r);
    }
    auto r = (n00b_chalk_io_result_t *)n00b_alloc(n00b_chalk_io_result_t);
    r->kind           = N00B_CHALK_OUT_SIDECAR;
    r->bytes          = n00b_buffer_from_bytes("", 0);
    r->sidecar_suffix = r".chalk";
    return n00b_result_ok(n00b_chalk_io_result_t *, r);
}

// Extract reads the sidecar at <path>.chalk (not the artifact bytes).
n00b_result_t(n00b_chalk_extract_result_t *)
n00b_chalk_sidecar_extract_file(n00b_string_t *path)
{
    auto rr = n00b_chalk_read_sidecar(path);
    if (n00b_result_is_err(rr)) {
        return n00b_result_err(n00b_chalk_extract_result_t *, 1);
    }
    return n00b_chalk_sidecar_parse_bytes(n00b_result_get(rr),
                                          N00B_CHALK_CODEC_SIDECAR_MODEL);
}

n00b_result_t(n00b_buffer_t *)
n00b_chalk_sidecar_hash_file(n00b_string_t *path)
{
    // The sidecar codec's unchalked hash is plain SHA-256 of the
    // artifact bytes (no canonical-form transformation). Streaming
    // keeps the resident set at one 64 KiB chunk regardless of
    // artifact size — e.g. a 50 GB ONNX file stays at ~64 KiB.
    return n00b_chalk_hash_file_stream(path);
}

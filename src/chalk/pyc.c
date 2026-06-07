/** @file src/chalk/pyc.c — Python bytecode (.pyc) codec.
 *
 *  In .pyc/.pyo/.pyd files chalk embeds the mark in-band by appending
 *  the JSON object after the python bytecode. The mark is located
 *  by searching for the chalk magic string "dadfedabbadabbed"; the
 *  enclosing `{` is the start of the mark and the matching `}` is its
 *  end. Bytes before the mark are the artifact body (hashed for HASH).
 */

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/sha256.h"
#include "core/alloc.h"
#include "parsers/json.h"
#include "adt/dict.h"
#include "chalk/n00b_chalk.h"
#include "internal/chalk/mark_internal.h"

#include <string.h>

#define MAGIC          N00B_CHALK_MAGIC_STRING
#define MAGIC_LEN      16

// -----------------------------------------------------------------------
// .pyc sanity check.
//
// Every CPython .pyc magic word ends with the bytes "\r\n" at offsets
// 2..3 — this is intentional in CPython's loader as a quick sanity
// signal. We use the same check to fail-fast on non-.pyc input
// passed to the buffer entry points; without this guard, an
// arbitrary buffer would trigger an unbounded find_magic scan.
// -----------------------------------------------------------------------

static bool
looks_like_pyc(n00b_buffer_t *bytes)
{
    // .pyc header is 16 bytes (magic + flags + ts + size). Reject
    // anything smaller; reject anything whose magic doesn't end in
    // "\r\n" (the canonical CPython sanity sentinel).
    return bytes && bytes->byte_len >= 16
        && bytes->data[2] == '\r' && bytes->data[3] == '\n';
}

// -----------------------------------------------------------------------
// Mark scan helpers (also useful to other in-band codecs; we'll lift
// them into mark.c when source/macho_wrap need them).
// -----------------------------------------------------------------------

// Find the first occurrence of MAGIC inside [data, data+len). Returns
// -1 if not present.
static int64_t
find_magic(const char *data, size_t len)
{
    if (len < MAGIC_LEN) return -1;
    for (size_t i = 0; i + MAGIC_LEN <= len; i++) {
        if (memcmp(data + i, MAGIC, MAGIC_LEN) == 0) {
            return (int64_t)i;
        }
    }
    return -1;
}

// Scan backward from `magic_pos` for the nearest `{` that opens the
// mark. Returns -1 if no opener found.
static int64_t
find_brace_back(const char *data, int64_t magic_pos)
{
    for (int64_t i = magic_pos; i >= 0; i--) {
        if (data[i] == '{') return i;
    }
    return -1;
}

// Starting at `{` at `start`, return the index just past the matching
// `}`. Brace counting with single-character string awareness. Returns
// -1 on malformed input.
static int64_t
find_mark_end(const char *data, size_t len, int64_t start)
{
    int     depth   = 0;
    bool    in_str  = false;
    bool    escape  = false;
    for (int64_t i = start; i < (int64_t)len; i++) {
        char c = data[i];
        if (in_str) {
            if (escape) {
                escape = false;
            }
            else if (c == '\\') {
                escape = true;
            }
            else if (c == '"') {
                in_str = false;
            }
            continue;
        }
        if (c == '"') {
            in_str = true;
        }
        else if (c == '{') {
            depth++;
        }
        else if (c == '}') {
            depth--;
            if (depth == 0) return i + 1;
        }
    }
    return -1;
}

// -----------------------------------------------------------------------
// Mark dict <-> json_node_t conversions
// -----------------------------------------------------------------------

// Convert a parsed JSON OBJECT node into a typed mark dict.
static n00b_dict_t(n00b_string_t *, n00b_json_node_t *) *
json_object_to_mark_dict(n00b_json_node_t *root)
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
// Codec entry points
// -----------------------------------------------------------------------

static n00b_buffer_t *
slice_bytes(n00b_buffer_t *in, size_t off, size_t len)
{
    return n00b_buffer_from_bytes(in->data + off, (int64_t)len);
}

static n00b_buffer_t *
sha256_of(const char *data, size_t len)
{
    n00b_sha256_digest_t words;
    n00b_sha256_hash(data, len, words);
    uint8_t bytes[32];
    for (int i = 0; i < 8; i++) {
        uint32_t w   = words[i];
        bytes[i * 4]     = (uint8_t)((w >> 24) & 0xff);
        bytes[i * 4 + 1] = (uint8_t)((w >> 16) & 0xff);
        bytes[i * 4 + 2] = (uint8_t)((w >> 8) & 0xff);
        bytes[i * 4 + 3] = (uint8_t)(w & 0xff);
    }
    return n00b_buffer_from_bytes((char *)bytes, 32);
}

// Locate the existing mark inside `bytes`. Returns mark_start in
// *out_mark_start and mark_end in *out_mark_end, both relative to
// bytes->data. Returns false if no mark is found.
static bool
locate_mark(n00b_buffer_t *bytes, size_t *out_mark_start, size_t *out_mark_end)
{
    const char *d   = bytes->data;
    size_t      n   = bytes->byte_len;
    int64_t     m   = find_magic(d, n);
    if (m < 0) return false;
    int64_t     bs  = find_brace_back(d, m);
    if (bs < 0) return false;
    int64_t     be  = find_mark_end(d, n, bs);
    if (be < 0) return false;
    *out_mark_start = (size_t)bs;
    *out_mark_end   = (size_t)be;
    return true;
}

// "pre" is the bytes before any existing mark — the unchalked body.
// Returns the unchalked-body byte_len (== bytes->byte_len if no mark).
static size_t
pre_len(n00b_buffer_t *bytes)
{
    size_t ms, me;
    if (locate_mark(bytes, &ms, &me)) return ms;
    return bytes->byte_len;
}

n00b_result_t(n00b_buffer_t *)
n00b_chalk_pyc_hash_buffer(n00b_buffer_t *bytes)
{
    if (!looks_like_pyc(bytes)) return n00b_result_err(n00b_buffer_t *, 1);
    size_t plen = pre_len(bytes);
    return n00b_result_ok(n00b_buffer_t *, sha256_of(bytes->data, plen));
}

n00b_result_t(n00b_chalk_io_result_t *)
n00b_chalk_pyc_insert_buffer(n00b_buffer_t *bytes, n00b_chalk_mark_t *mark)
{
    if (!mark || !looks_like_pyc(bytes)) {
        return n00b_result_err(n00b_chalk_io_result_t *, 1);
    }

    size_t ms, me;
    bool   had_mark = locate_mark(bytes, &ms, &me);
    size_t pre      = had_mark ? ms : bytes->byte_len;

    // Compute unchalked sha256 over the pre region.
    auto hash_buf = sha256_of(bytes->data, pre);

    auto fin = n00b_chalk_mark_finalize(mark, hash_buf);
    if (n00b_result_is_err(fin)) {
        return n00b_result_err(n00b_chalk_io_result_t *, 2);
    }
    n00b_buffer_t *encoded = n00b_result_get(fin);

    // Build pre + encoded + post (post stripped of leading whitespace).
    size_t post_off = had_mark ? me : bytes->byte_len;
    size_t post_len = bytes->byte_len - post_off;
    while (post_len > 0
           && (bytes->data[post_off] == ' '
               || bytes->data[post_off] == '\n'
               || bytes->data[post_off] == '\r'
               || bytes->data[post_off] == '\t')) {
        post_off++;
        post_len--;
    }

    size_t out_cap = pre + encoded->byte_len + post_len;
    char  *out     = n00b_alloc_array(char, out_cap);
    memcpy(out, bytes->data, pre);
    memcpy(out + pre, encoded->data, encoded->byte_len);
    if (post_len) memcpy(out + pre + encoded->byte_len,
                          bytes->data + post_off, post_len);

    auto result = (n00b_chalk_io_result_t *)
                      n00b_alloc(n00b_chalk_io_result_t);
    result->kind           = N00B_CHALK_OUT_IN_BAND;
    result->bytes          = n00b_buffer_from_bytes(out, (int64_t)out_cap);
    result->sidecar_suffix = nullptr;
    return n00b_result_ok(n00b_chalk_io_result_t *, result);
}

n00b_result_t(n00b_chalk_io_result_t *)
n00b_chalk_pyc_delete_buffer(n00b_buffer_t *bytes)
{
    if (!looks_like_pyc(bytes)) {
        return n00b_result_err(n00b_chalk_io_result_t *, 1);
    }

    size_t ms, me;
    n00b_buffer_t *out;
    if (locate_mark(bytes, &ms, &me)) {
        out = slice_bytes(bytes, 0, ms);
    }
    else {
        out = slice_bytes(bytes, 0, bytes->byte_len);
    }

    auto r = (n00b_chalk_io_result_t *)n00b_alloc(n00b_chalk_io_result_t);
    r->kind           = N00B_CHALK_OUT_IN_BAND;
    r->bytes          = out;
    r->sidecar_suffix = nullptr;
    return n00b_result_ok(n00b_chalk_io_result_t *, r);
}

n00b_result_t(n00b_chalk_extract_result_t *)
n00b_chalk_pyc_extract_buffer(n00b_buffer_t *bytes)
{
    if (!looks_like_pyc(bytes)) {
        return n00b_result_err(n00b_chalk_extract_result_t *, 1);
    }
    size_t ms, me;
    if (!locate_mark(bytes, &ms, &me)) {
        return n00b_result_err(n00b_chalk_extract_result_t *, 2);
    }
    const char       *err  = nullptr;
    n00b_json_node_t *root = n00b_json_parse(bytes->data + ms,
                                             me - ms, &err);
    if (!n00b_json_is_object(root)) {
        return n00b_result_err(n00b_chalk_extract_result_t *, 3);
    }

    auto r = (n00b_chalk_extract_result_t *)
                 n00b_alloc(n00b_chalk_extract_result_t);
    r->codec  = N00B_CHALK_CODEC_PYC;
    r->source = N00B_CHALK_OUT_IN_BAND;
    r->mark   = json_object_to_mark_dict(root);
    return n00b_result_ok(n00b_chalk_extract_result_t *, r);
}

// File-mode entry points: read bytes via the VFS helper, dispatch
// to the buffer-mode entry point, write the result back.
#include "internal/chalk/file_io.h"

n00b_result_t(n00b_chalk_io_result_t *)
n00b_chalk_pyc_insert_file(n00b_string_t *path, n00b_chalk_mark_t *mark)
{
    return n00b_chalk_file_insert_via(path, mark,
                                      n00b_chalk_pyc_insert_buffer);
}

n00b_result_t(n00b_chalk_io_result_t *)
n00b_chalk_pyc_delete_file(n00b_string_t *path)
{
    return n00b_chalk_file_delete_via(path,
                                      n00b_chalk_pyc_delete_buffer);
}

n00b_result_t(n00b_chalk_extract_result_t *)
n00b_chalk_pyc_extract_file(n00b_string_t *path)
{
    return n00b_chalk_file_extract_via(path,
                                       n00b_chalk_pyc_extract_buffer);
}

n00b_result_t(n00b_buffer_t *)
n00b_chalk_pyc_hash_file(n00b_string_t *path)
{
    return n00b_chalk_file_hash_via(path,
                                    n00b_chalk_pyc_hash_buffer);
}

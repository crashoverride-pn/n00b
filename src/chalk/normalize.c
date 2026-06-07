/** @file src/chalk/normalize.c — chalk binary normalization.
 *
 *  Reproduces the byte format of chalk/src/normalize.nim. Output is
 *  fed to SHA-256 to produce METADATA_HASH; chalk-the-tool then
 *  re-normalizes our mark on extract and validates the same hash, so
 *  this MUST byte-match the Nim implementation.
 *
 *  Tag table:
 *    \x01  string  → tag + uint32-LE length + UTF-8 bytes
 *    \x02  int     → tag + uint64-LE (unsigned bit-pattern of int64)
 *    \x03  bool    → tag + \x00 or \x01
 *    \x04  array   → tag + uint32-LE count + N encoded items
 *    \x05  table   → tag + uint32-LE count + (encoded-key + encoded-value)*
 *                    with keys sorted lexicographically, ignoring keys in
 *                    {MAGIC, SIGNATURE, SIGN_PARAMS}.
 *    \x06  float   → tag followed by 0 bytes (replicates chalk's
 *                    long-standing floatToStr stub; no in-scope key is
 *                    a float)
 *    \x07  null    → single tag byte
 *
 *  Endianness is host LE; chalk uses cast[array[N, char]] of the raw
 *  uint, which is LE on every target we support (x86_64, aarch64).
 */

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/alloc.h"
#include "core/atomic.h"
#include "parsers/json.h"
#include "adt/list.h"
#include "adt/dict.h"
#include "internal/chalk/normalize.h"

#include <string.h>   // memcpy/memcmp — header-only per NCC.md exemption

// -----------------------------------------------------------------------
// Growable byte builder (private)
// -----------------------------------------------------------------------

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} byte_builder_t;

static void
bb_init(byte_builder_t *bb)
{
    bb->cap  = 256;
    bb->len  = 0;
    bb->data = n00b_alloc_array(char, bb->cap);
}

static void
bb_ensure(byte_builder_t *bb, size_t add)
{
    size_t need = bb->len + add;
    if (need <= bb->cap) return;
    size_t new_cap = bb->cap;
    while (new_cap < need) new_cap *= 2;
    char *grown = n00b_alloc_array(char, new_cap);
    memcpy(grown, bb->data, bb->len);
    bb->data = grown;
    bb->cap  = new_cap;
}

static void
bb_put(byte_builder_t *bb, const void *p, size_t n)
{
    bb_ensure(bb, n);
    memcpy(bb->data + bb->len, p, n);
    bb->len += n;
}

static void
bb_put_byte(byte_builder_t *bb, uint8_t b)
{
    bb_ensure(bb, 1);
    bb->data[bb->len++] = (char)b;
}

static void
bb_put_u32_le(byte_builder_t *bb, uint32_t v)
{
    uint8_t buf[4] = {
        (uint8_t)(v & 0xff),
        (uint8_t)((v >> 8) & 0xff),
        (uint8_t)((v >> 16) & 0xff),
        (uint8_t)((v >> 24) & 0xff),
    };
    bb_put(bb, buf, 4);
}

static void
bb_put_u64_le(byte_builder_t *bb, uint64_t v)
{
    uint8_t buf[8] = {
        (uint8_t)(v & 0xff),
        (uint8_t)((v >> 8) & 0xff),
        (uint8_t)((v >> 16) & 0xff),
        (uint8_t)((v >> 24) & 0xff),
        (uint8_t)((v >> 32) & 0xff),
        (uint8_t)((v >> 40) & 0xff),
        (uint8_t)((v >> 48) & 0xff),
        (uint8_t)((v >> 56) & 0xff),
    };
    bb_put(bb, buf, 8);
}

// -----------------------------------------------------------------------
// Per-tag encoders
// -----------------------------------------------------------------------

static void
emit_string_raw(byte_builder_t *bb, const char *data, size_t len)
{
    bb_put_byte(bb, 0x01);
    bb_put_u32_le(bb, (uint32_t)len);
    bb_put(bb, data, len);
}

static void emit_json(byte_builder_t *bb, n00b_json_node_t *v);

// Pair used during the outer + nested object table sort.
typedef struct {
    const char             *key_data;
    size_t                  key_len;
    n00b_json_node_t *value;
} pair_t;

static int
pair_cmp(const void *a, const void *b)
{
    const pair_t *pa = (const pair_t *)a;
    const pair_t *pb = (const pair_t *)b;
    size_t        n  = pa->key_len < pb->key_len ? pa->key_len : pb->key_len;
    int           c  = memcmp(pa->key_data, pb->key_data, n);
    if (c != 0) return c;
    if (pa->key_len < pb->key_len) return -1;
    if (pa->key_len > pb->key_len) return 1;
    return 0;
}

// Matches chalk's `ignore_when_normalizing` default from
// chalk/src/configs/chalk.c42spec:3280-3283 verbatim:
//   ["MAGIC", "METADATA_HASH", "METADATA_ID",
//    "SIGNING", "SIGNATURE", "EMBEDDED_CHALK"]
static bool
is_ignored_key(const char *key, size_t len)
{
    if (len == 5  && memcmp(key, "MAGIC",          5)  == 0) return true;
    if (len == 13 && memcmp(key, "METADATA_HASH",  13) == 0) return true;
    if (len == 11 && memcmp(key, "METADATA_ID",    11) == 0) return true;
    if (len == 7  && memcmp(key, "SIGNING",        7)  == 0) return true;
    if (len == 9  && memcmp(key, "SIGNATURE",      9)  == 0) return true;
    if (len == 14 && memcmp(key, "EMBEDDED_CHALK", 14) == 0) return true;
    return false;
}

static void
emit_pair_table(byte_builder_t *bb, pair_t *pairs, size_t n)
{
    // Filter out ignored keys in place.
    size_t kept = 0;
    for (size_t i = 0; i < n; i++) {
        if (!is_ignored_key(pairs[i].key_data, pairs[i].key_len)) {
            if (kept != i) pairs[kept] = pairs[i];
            kept++;
        }
    }
    qsort(pairs, kept, sizeof(pair_t), pair_cmp);

    bb_put_byte(bb, 0x05);
    bb_put_u32_le(bb, (uint32_t)kept);
    for (size_t i = 0; i < kept; i++) {
        emit_string_raw(bb, pairs[i].key_data, pairs[i].key_len);
        emit_json(bb, pairs[i].value);
    }
}

static void
emit_object(byte_builder_t *bb, n00b_json_node_t *obj)
{
    n00b_json_object_t *d = n00b_json_as_object(obj);
    size_t              n = d == nullptr ? 0 : (size_t)n00b_atomic_load(&d->length);

    pair_t *pairs = n ? n00b_alloc_array(pair_t, n) : nullptr;
    size_t  pi    = 0;

    if (d != nullptr) {
        n00b_dict_foreach(d, key, value, {
            if (pi >= n) break;
            pairs[pi].key_data = key == nullptr ? nullptr : key->data;
            pairs[pi].key_len  = key == nullptr ? 0 : key->u8_bytes;
            pairs[pi].value    = value;
            pi++;
        });
    }
    emit_pair_table(bb, pairs, pi);
}

static void
emit_array(byte_builder_t *bb, n00b_json_node_t *arr)
{
    bb_put_byte(bb, 0x04);
    size_t n = n00b_json_array_len(arr);
    bb_put_u32_le(bb, (uint32_t)n);
    for (size_t i = 0; i < n; i++) {
        n00b_json_node_t *item = n00b_json_array_get(arr, i);
        emit_json(bb, item);
    }
}

static void
emit_json(byte_builder_t *bb, n00b_json_node_t *v)
{
    if (n00b_json_is_null(v)) {
        bb_put_byte(bb, 0x07);
        return;
    }
    switch (n00b_json_type(v)) {
    case N00B_JSON_BOOL:
        bb_put_byte(bb, 0x03);
        bb_put_byte(bb, n00b_json_as_bool(v) ? 0x01 : 0x00);
        return;
    case N00B_JSON_INT:
        bb_put_byte(bb, 0x02);
        bb_put_u64_le(bb, (uint64_t)n00b_json_as_i64(v));
        return;
    case N00B_JSON_DOUBLE:
        // Replicate chalk's floatToStr stub: tag byte, no payload.
        // floatToStr() in chalk's normalize.nim allocates capacity but
        // never writes the float bytes. No in-scope chalk key is a
        // float; we keep parity for any user-provided ATTESTATION
        // contents that contain doubles.
        bb_put_byte(bb, 0x06);
        return;
    case N00B_JSON_STRING:
    {
        n00b_string_t *s = n00b_json_as_string(v);
        emit_string_raw(bb,
                        s == nullptr ? nullptr : s->data,
                        s == nullptr ? 0 : s->u8_bytes);
        return;
    }
    case N00B_JSON_ARRAY:
        emit_array(bb, v);
        return;
    case N00B_JSON_OBJECT:
        emit_object(bb, v);
        return;
    case N00B_JSON_NULL:
        bb_put_byte(bb, 0x07);
        return;
    }
}

// -----------------------------------------------------------------------
// Public entry point
// -----------------------------------------------------------------------

n00b_buffer_t *
n00b_chalk_normalize(n00b_dict_t(n00b_string_t *, n00b_json_node_t *) *dict)
{
    byte_builder_t bb;
    bb_init(&bb);

    // Snapshot the outer mark dict into the pair_t array so we can
    // sort + filter uniformly with the nested-object path.
    pair_t *pairs    = nullptr;
    size_t  pair_cap = 0;
    size_t  pair_len = 0;

    n00b_dict_foreach(dict, k, v, {
        if (pair_len == pair_cap) {
            size_t new_cap = pair_cap ? pair_cap * 2 : 16;
            pair_t *grown  = n00b_alloc_array(pair_t, new_cap);
            if (pairs) memcpy(grown, pairs, pair_len * sizeof(pair_t));
            pairs    = grown;
            pair_cap = new_cap;
        }
        pairs[pair_len].key_data = k->data;
        pairs[pair_len].key_len  = k->u8_bytes;
        pairs[pair_len].value    = v;
        pair_len++;
    });

    emit_pair_table(&bb, pairs, pair_len);
    return n00b_buffer_from_bytes(bb.data, (int64_t)bb.len);
}

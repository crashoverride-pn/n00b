/** @file src/chalk/mark.c — mark assembly and canonical serialization.
 *
 *  Owns the six chalk-mark keys libchalk emits:
 *   - MAGIC                     literal "dadfedabbadabbed"
 *   - CHALK_ID                  idFormat(sha256(unchalked))
 *   - HASH                      sha256_hex(unchalked)
 *   - CHALK_VERSION             literal "2.0.0"
 *   - TIMESTAMP_WHEN_CHALKED    int64 ms since epoch
 *   - METADATA_HASH             sha256_hex(normalize(mark sans ignored keys))
 *   - METADATA_ID               idFormat(sha256(normalize(...)))
 *   - ATTESTATION (optional)    opaque caller JSON
 *
 *  The serialized output places MAGIC first; chalk's mark scanner
 *  (chalkjson.nim:71) requires that exact prefix.
 */

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/sha256.h"
#include "core/alloc.h"
#include "core/time.h"
#include "parsers/json.h"
#include "adt/dict.h"
#include "internal/chalk/base32v.h"
#include "internal/chalk/mark_internal.h"
#include "internal/chalk/normalize.h"

#include <string.h>

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

static const char k_hex[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
};

static n00b_string_t *
sha256_to_hex_string(const uint8_t digest[32])
{
    char out[64];
    for (int i = 0; i < 32; i++) {
        out[i * 2]     = k_hex[(digest[i] >> 4) & 0xf];
        out[i * 2 + 1] = k_hex[digest[i] & 0xf];
    }
    return n00b_string_from_raw(out, 64);
}

// Convert n00b_sha256_digest_t (8 uint32) to 32 big-endian bytes.
static void
sha256_words_to_bytes(const n00b_sha256_digest_t words, uint8_t out[32])
{
    for (int i = 0; i < 8; i++) {
        uint32_t w   = words[i];
        out[i * 4]     = (uint8_t)((w >> 24) & 0xff);
        out[i * 4 + 1] = (uint8_t)((w >> 16) & 0xff);
        out[i * 4 + 2] = (uint8_t)((w >> 8) & 0xff);
        out[i * 4 + 3] = (uint8_t)(w & 0xff);
    }
}

static int64_t
now_ms(void)
{
    return n00b_us_timestamp() / 1000;
}

// Put helper that wraps a C-string key + json_node value into the
// outer typed dict.
static void
mark_put(n00b_dict_t(n00b_string_t *, n00b_json_node_t *) *d,
         const char       *key,
         n00b_json_node_t *value)
{
    n00b_string_t   *k = n00b_string_from_cstr(key);
    n00b_dict_put(d, k, value);
}

// -----------------------------------------------------------------------
// Public mark API
// -----------------------------------------------------------------------

n00b_chalk_mark_t *
n00b_chalk_mark_new(void)
{
    n00b_chalk_mark_t *m = n00b_alloc(n00b_chalk_mark_t);
    m->dict        = n00b_alloc(n00b_dict_t(n00b_string_t *, n00b_json_node_t *));
    n00b_dict_init(m->dict);
    m->attestation = nullptr;
    m->finalized   = false;
    return m;
}

void
n00b_chalk_mark_free(n00b_chalk_mark_t *m)
{
    // mark_new allocates m + m->dict through n00b's pluggable
    // allocator surface. Pair with n00b_free here for correctness
    // under any backing (GC: no-op; arena/refcount/etc: explicit
    // cleanup). m->attestation is a borrowed pointer set by
    // n00b_chalk_mark_set_attestation; caller owns its lifetime.
    if (!m) return;
    if (m->dict) {
        n00b_free(m->dict);
    }
    n00b_free(m);
}

n00b_result_t(bool)
n00b_chalk_mark_set_attestation(n00b_chalk_mark_t *mark,
                                n00b_json_node_t  *value)
{
    if (!mark) return n00b_result_err(bool, 1);
    mark->attestation = value;
    return n00b_result_ok(bool, true);
}

n00b_dict_t(n00b_string_t *, n00b_json_node_t *) *
n00b_chalk_mark_as_dict(n00b_chalk_mark_t *mark)
{
    return mark ? mark->dict : nullptr;
}

// -----------------------------------------------------------------------
// Canonical JSON serializer
// -----------------------------------------------------------------------

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} j_builder_t;

static void
jb_init(j_builder_t *jb)
{
    jb->cap  = 512;
    jb->len  = 0;
    jb->data = n00b_alloc_array(char, jb->cap);
}

static void
jb_ensure(j_builder_t *jb, size_t add)
{
    size_t need = jb->len + add;
    if (need <= jb->cap) return;
    size_t new_cap = jb->cap;
    while (new_cap < need) new_cap *= 2;
    char *grown = n00b_alloc_array(char, new_cap);
    memcpy(grown, jb->data, jb->len);
    jb->data = grown;
    jb->cap  = new_cap;
}

static void
jb_put(j_builder_t *jb, const char *p, size_t n)
{
    jb_ensure(jb, n);
    memcpy(jb->data + jb->len, p, n);
    jb->len += n;
}

static void
jb_putc(j_builder_t *jb, char c)
{
    jb_ensure(jb, 1);
    jb->data[jb->len++] = c;
}

static void
jb_put_cstr(j_builder_t *jb, const char *s)
{
    jb_put(jb, s, strlen(s));
}

static void
jb_put_kv(j_builder_t *jb, const char *key, n00b_json_node_t *value, bool first)
{
    if (!first) jb_put_cstr(jb, ", ");
    jb_putc(jb, '"');
    jb_put_cstr(jb, key);
    jb_put_cstr(jb, "\" : ");
    // Canonical mode produces byte-stable output independent of
    // dict-insertion order — required so the ATTESTATION subtree
    // (and any other nested object value) round-trips byte-stably
    // through libchalk parse + reserialize.
    char *encoded = n00b_json_encode(value, .canonical = true);
    jb_put_cstr(jb, encoded);
}

// Emit the dict as `{ "MAGIC" : ..., <rest in fixed order> }`. Keys
// not in the known set are appended in dict-iteration order after
// the known ones. Chalk only requires the `{ "MAGIC" : ` prefix.
static const char *k_known_order[] = {
    "CHALK_ID",
    "CHALK_VERSION",
    "TIMESTAMP_WHEN_CHALKED",
    "HASH",
    "METADATA_ID",
    "ATTESTATION",
};
#define K_KNOWN_LEN (sizeof(k_known_order) / sizeof(k_known_order[0]))

static n00b_buffer_t *
serialize_mark(n00b_dict_t(n00b_string_t *, n00b_json_node_t *) *dict)
{
    j_builder_t jb;
    jb_init(&jb);
    jb_put_cstr(&jb, "{ ");

    // MAGIC first.
    bool first = true;
    n00b_dict_foreach(dict, k, v, {
        if (k->u8_bytes == 5 && memcmp(k->data, "MAGIC", 5) == 0) {
            jb_put_kv(&jb, "MAGIC", v, first);
            first = false;
        }
    });

    // Known keys in chalk's documented order.
    for (size_t i = 0; i < K_KNOWN_LEN; i++) {
        const char *target = k_known_order[i];
        size_t      tlen   = strlen(target);
        n00b_dict_foreach(dict, k, v, {
            if (k->u8_bytes == tlen && memcmp(k->data, target, tlen) == 0) {
                jb_put_kv(&jb, target, v, first);
                first = false;
            }
        });
    }

    // Any remaining keys (caller-added beyond the six known) emitted
    // in dict-iteration order, skipping ones already written.
    n00b_dict_foreach(dict, k, v, {
        if (k->u8_bytes == 5 && memcmp(k->data, "MAGIC", 5) == 0) continue;
        bool skip = false;
        for (size_t j = 0; j < K_KNOWN_LEN; j++) {
            size_t tl = strlen(k_known_order[j]);
            if (k->u8_bytes == tl
                && memcmp(k->data, k_known_order[j], tl) == 0) {
                skip = true;
                break;
            }
        }
        if (!skip) {
            // Need a NUL-terminated key for jb_put_kv.
            char *kbuf = n00b_alloc_array(char, k->u8_bytes + 1);
            memcpy(kbuf, k->data, k->u8_bytes);
            kbuf[k->u8_bytes] = '\0';
            jb_put_kv(&jb, kbuf, v, first);
            first = false;
        }
    });

    jb_put_cstr(&jb, " }");
    return n00b_buffer_from_bytes(jb.data, (int64_t)jb.len);
}

// -----------------------------------------------------------------------
// Finalize
// -----------------------------------------------------------------------

n00b_result_t(n00b_buffer_t *)
n00b_chalk_mark_finalize(n00b_chalk_mark_t *mark,
                         n00b_buffer_t     *unchalked_sha256_32)
{
    if (!mark || !unchalked_sha256_32
        || unchalked_sha256_32->byte_len != 32) {
        return n00b_result_err(n00b_buffer_t *, 1);
    }
    if (mark->finalized) {
        return n00b_result_err(n00b_buffer_t *, 2);
    }

    const uint8_t *unchalked = (const uint8_t *)unchalked_sha256_32->data;

    // ---- CHALK_ID + HASH (derived from unchalked digest) ---------------
    // CHALK_ID = idFormat(hex(sha256)) per chalk's defaultChalkId, which
    // calls idFormat directly on the codec's getUnchalkedHash return value
    // — and every codec's hook returns a hex string (chalk/src/plugins/
    // codecPythonPyc.nim:83, etc.).
    n00b_string_t *chalk_id_str = n00b_chalk_id_format_sha256_hex(unchalked);
    n00b_string_t *hash_hex_str = sha256_to_hex_string(unchalked);

    // ---- Static keys ---------------------------------------------------
    mark_put(mark->dict, "MAGIC",
             n00b_json_string_new(N00B_CHALK_MAGIC_STRING));
    mark_put(mark->dict, "CHALK_ID",
             n00b_json_string_new(chalk_id_str->data));
    mark_put(mark->dict, "CHALK_VERSION",
             n00b_json_string_new(N00B_CHALK_VERSION_STRING));
    mark_put(mark->dict, "HASH",
             n00b_json_string_new(hash_hex_str->data));
    mark_put(mark->dict, "TIMESTAMP_WHEN_CHALKED",
             n00b_json_int_new(now_ms()));
    if (mark->attestation) {
        mark_put(mark->dict, "ATTESTATION", mark->attestation);
    }

    // ---- METADATA_ID (derived from normalize sha256) -------------------
    // METADATA_HASH is intentionally NOT emitted. chalk's system plugin
    // (system.nim:66-75) makes METADATA_ID validation mandatory but
    // METADATA_HASH validation conditional on presence — leaving it out
    // is safe and keeps the mark smaller.
    n00b_buffer_t       *norm = n00b_chalk_normalize(mark->dict);
    n00b_sha256_digest_t mhw;
    n00b_sha256_hash(norm->data, norm->byte_len, mhw);
    uint8_t mh_bytes[32];
    sha256_words_to_bytes(mhw, mh_bytes);

    // METADATA_ID = idFormat(raw sha256 bytes) per chalkjson.nim:525,
    // which passes the raw Sha256Digest to idFormat directly.
    n00b_string_t *meta_id = n00b_chalk_id_format_sha256_bytes(mh_bytes);
    mark_put(mark->dict, "METADATA_ID",
             n00b_json_string_new(meta_id->data));

    mark->finalized = true;
    return n00b_result_ok(n00b_buffer_t *, serialize_mark(mark->dict));
}

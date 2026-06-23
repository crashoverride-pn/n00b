/* src/attest/statement.c — in-toto Statement v1 builder body.
 *
 * Implements the surface declared in
 * include/attest/n00b_attest_statement.h:
 *   - n00b_attest_statement_new
 *   - n00b_attest_statement_add_subject
 *   - n00b_attest_statement_set_predicate_type   (COPY semantics, D-030/W-2)
 *   - n00b_attest_statement_set_predicate_json   (COPY semantics, D-030/W-2)
 *   - n00b_attest_statement_serialize
 *   - n00b_attest_statement_parse
 *
 * Allocator discipline: every internal allocation threads the kwarg
 * `.allocator` directly into the called allocating function (FR-21).
 *
 * Canonical-form note (D-024): we use libn00b's `n00b_json_encode(.pretty
 * = false)` directly. Compact, byte-stable-per-construction is enough
 * for our DSSE flow — the verifier never re-encodes.
 */

#include <attest/n00b_attest.h>

#include "core/buffer.h"
#include "core/string.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "parsers/json.h"
#include "adt/list.h"
#include "adt/result.h"

#include "internal/attest/json_util.h"

#include <string.h>

// ---------------------------------------------------------------------------
// Module-domain error codes (negative to avoid collision with errno) are now
// declared in `include/attest/n00b_attest_error.h` (V-2 fix during WP-002
// Phase 3 — see D-031 A-1 closure). The umbrella header pulls them in.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// in-toto Statement v1 constants.
// ---------------------------------------------------------------------------

static const char k_statement_type_uri[] = "https://in-toto.io/Statement/v1";

// ---------------------------------------------------------------------------
// Private types.
//
// A subject entry: { name: string, digest: { algorithm-name -> hex-bytes } }.
// We carry the name as n00b_string_t * (per guideline §2.2), and the
// digest as a parallel pair of lists (algorithm name + hex-encoded bytes)
// so we can support multi-algorithm digest maps without forcing a typed
// dict for what is, at most, a handful of entries per subject.
// ---------------------------------------------------------------------------

typedef struct {
    n00b_string_t *name;
    // digest_algs[i] is the algorithm name ("sha256", "sha512", …);
    // digest_hexes[i] is the lowercase-hex encoding of the digest bytes.
    n00b_list_t(n00b_string_t *) digest_algs;
    n00b_list_t(n00b_string_t *) digest_hexes;
} subject_entry_t;

struct n00b_attest_statement {
    // Each subject entry is allocated through `allocator` and stored
    // via pointer.
    n00b_list_t(subject_entry_t *) subjects;
    // predicate type URI — owned copy.
    n00b_string_t *predicate_type;
    // predicate JSON bytes — owned copy of the input.
    n00b_buffer_t *predicate_json;
    // Allocator that owns this builder + every byte it produces.
    n00b_allocator_t *allocator;
};

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

static const char k_hex_lower[] = "0123456789abcdef";

static n00b_string_t *
hex_encode_bytes(const uint8_t *data, size_t len, n00b_allocator_t *allocator)
{
    char *out = n00b_alloc_array_with_opts(char,
                                           len * 2,
                                           &(n00b_alloc_opts_t){
                                               .allocator = allocator,
                                           });
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = k_hex_lower[(data[i] >> 4) & 0xf];
        out[i * 2 + 1] = k_hex_lower[data[i] & 0xf];
    }
    return n00b_string_from_raw(out,
                                (int64_t)(len * 2),
                                .allocator = allocator);
}

static n00b_string_t *
copy_string(n00b_string_t *src, n00b_allocator_t *allocator)
{
    if (src == nullptr) {
        return nullptr;
    }
    return n00b_string_from_raw(src->data,
                                (int64_t)src->u8_bytes,
                                .allocator = allocator);
}

static n00b_buffer_t *
copy_buffer(n00b_buffer_t *src, n00b_allocator_t *allocator)
{
    if (src == nullptr) {
        return nullptr;
    }
    return n00b_buffer_from_bytes(src->data,
                                  (int64_t)src->byte_len,
                                  .allocator = allocator);
}

// Allocate a NUL-terminated copy of an n00b_string_t's bytes for JSON
// helpers that need C-string keys / values. The copy lives in the
// statement's allocator (or runtime default).
static char *
strdup_in(const char *src, size_t len, n00b_allocator_t *allocator)
{
    char *out = n00b_alloc_array_with_opts(char,
                                           len + 1,
                                           &(n00b_alloc_opts_t){
                                               .allocator = allocator,
                                           });
    if (len > 0) {
        memcpy(out, src, len);
    }
    out[len] = '\0';
    return out;
}

static char *
nstr_to_cstr(n00b_string_t *s, n00b_allocator_t *allocator)
{
    return strdup_in(s->data, s->u8_bytes, allocator);
}

// ---------------------------------------------------------------------------
// Public surface — construction / mutation.
// ---------------------------------------------------------------------------

n00b_attest_statement_t *
n00b_attest_statement_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_attest_statement_t *st = n00b_alloc_with_opts(
        n00b_attest_statement_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    st->allocator      = allocator;
    st->predicate_type = nullptr;
    st->predicate_json = nullptr;

    st->subjects = n00b_list_new(subject_entry_t *,
                                 .allocator = allocator);

    return st;
}

n00b_result_t(bool)
n00b_attest_statement_add_subject(n00b_attest_statement_t *st) _kargs
{
    n00b_string_t    *name      = nullptr;
    n00b_buffer_t    *digest    = nullptr;
    n00b_allocator_t *allocator = nullptr;
}
{
    if (st == nullptr || name == nullptr || digest == nullptr) {
        return n00b_result_err(bool, N00B_ATTEST_ERR_STMT_BAD_INPUT);
    }
    if (name->u8_bytes == 0 || digest->byte_len == 0) {
        return n00b_result_err(bool, N00B_ATTEST_ERR_STMT_BAD_INPUT);
    }

    // Threading rule: prefer the call-site allocator kwarg; if absent,
    // use the one captured at builder construction time.
    n00b_allocator_t *alloc_for_call = allocator ? allocator : st->allocator;

    subject_entry_t *entry = n00b_alloc_with_opts(
        subject_entry_t,
        &(n00b_alloc_opts_t){
            .allocator = alloc_for_call,
        });

    entry->name         = copy_string(name, alloc_for_call);
    entry->digest_algs  = n00b_list_new(n00b_string_t *,
                                        .allocator = alloc_for_call);
    entry->digest_hexes = n00b_list_new(n00b_string_t *,
                                        .allocator = alloc_for_call);

    // v1 sha256: the buffer's bytes are the raw 32-byte digest. We
    // hex-encode lowercase; the JSON shape uses `digest.sha256` as a
    // lowercase-hex string.
    n00b_string_t *alg = r"sha256";
    n00b_string_t *hex = hex_encode_bytes((const uint8_t *)digest->data,
                                          digest->byte_len,
                                          alloc_for_call);

    n00b_list_push(entry->digest_algs, alg);
    n00b_list_push(entry->digest_hexes, hex);

    n00b_list_push(st->subjects, entry);

    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_attest_statement_set_predicate_type(n00b_attest_statement_t *st,
                                         n00b_string_t           *type_uri)
_kargs {
    n00b_allocator_t *allocator = nullptr;
}
{
    if (st == nullptr || type_uri == nullptr || type_uri->u8_bytes == 0) {
        return n00b_result_err(bool, N00B_ATTEST_ERR_STMT_BAD_INPUT);
    }

    n00b_allocator_t *alloc_for_call = allocator ? allocator : st->allocator;

    // D-030 / W-2: COPY semantics. Caller may free `type_uri`
    // immediately after this call.
    st->predicate_type = copy_string(type_uri, alloc_for_call);
    return n00b_result_ok(bool, true);
}

n00b_option_t(n00b_string_t *)
    n00b_attest_statement_get_predicate_type(n00b_attest_statement_t *st)
{
    if (st == nullptr || st->predicate_type == nullptr) {
        return n00b_option_none(n00b_string_t *);
    }
    return n00b_option_set(n00b_string_t *, st->predicate_type);
}

n00b_option_t(n00b_string_t *)
    n00b_attest_subject_get_digest_sha256(n00b_attest_statement_t *st,
                                          size_t subject_index)
_kargs {
    n00b_allocator_t *allocator = nullptr;
}
{
    if (st == nullptr) {
        return n00b_option_none(n00b_string_t *);
    }
    if (subject_index >= st->subjects.len) {
        return n00b_option_none(n00b_string_t *);
    }
    subject_entry_t *entry = st->subjects.data[subject_index];
    if (entry == nullptr) {
        return n00b_option_none(n00b_string_t *);
    }

    // Threading rule: prefer the call-site allocator kwarg; if absent,
    // use the one captured at builder construction time (matches the
    // pattern used by _add_subject / _set_predicate_*).
    n00b_allocator_t *alloc_for_call = allocator ? allocator : st->allocator;

    // Walk the parallel digest_algs / digest_hexes arrays looking
    // for the first sha256 entry. Linear scan is fine — subjects
    // carry at most a handful of digest algs each.
    for (size_t i = 0; i < entry->digest_algs.len; i++) {
        n00b_string_t *alg = entry->digest_algs.data[i];
        if (alg == nullptr) continue;
        if (alg->u8_bytes != 6) continue;
        if (memcmp(alg->data, "sha256", 6) != 0) continue;

        n00b_string_t *hex = entry->digest_hexes.data[i];
        if (hex == nullptr) return n00b_option_none(n00b_string_t *);
        return n00b_option_set(n00b_string_t *,
                               copy_string(hex, alloc_for_call));
    }
    return n00b_option_none(n00b_string_t *);
}

n00b_result_t(bool)
n00b_attest_statement_set_predicate_json(n00b_attest_statement_t *st,
                                         n00b_buffer_t           *predicate_json)
_kargs {
    n00b_allocator_t *allocator = nullptr;
}
{
    if (st == nullptr || predicate_json == nullptr
        || predicate_json->byte_len == 0) {
        return n00b_result_err(bool, N00B_ATTEST_ERR_STMT_BAD_INPUT);
    }

    n00b_allocator_t *alloc_for_call = allocator ? allocator : st->allocator;

    // Eagerly validate that the predicate parses as JSON — the schema
    // contract says we re-emit it canonicalized at serialize time, so
    // it must be parseable now. We don't keep the parsed tree; the
    // canonicalization round-trip happens at serialize time.
    const char       *err  = nullptr;
    n00b_json_node_t *node = n00b_json_parse(predicate_json->data,
                                             predicate_json->byte_len,
                                             &err);
    if (node == nullptr) {
        return n00b_result_err(bool, N00B_ATTEST_ERR_STMT_BAD_JSON);
    }

    // D-030 / W-2: COPY semantics. Caller may free `predicate_json`
    // immediately after this call.
    st->predicate_json = copy_buffer(predicate_json, alloc_for_call);
    return n00b_result_ok(bool, true);
}

// ---------------------------------------------------------------------------
// Serialize.
//
// Build a JSON object {_type, subject, predicateType, predicate} via
// libn00b's JSON primitives, then encode with n00b_json_encode(.pretty =
// false). The embedded predicate is re-parsed from the stored copy and
// re-emitted so it inherits the same compact canonicalization (D-024).
// ---------------------------------------------------------------------------

n00b_result_t(n00b_buffer_t *)
n00b_attest_statement_serialize(n00b_attest_statement_t *st) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (st == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_STMT_BAD_INPUT);
    }
    if (st->predicate_type == nullptr || st->predicate_json == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_STMT_MISSING_FIELD);
    }

    n00b_allocator_t *alloc_for_call = allocator ? allocator : st->allocator;

    n00b_json_node_t *root = n00b_json_object_new();

    // `_type`
    n00b_json_object_put(root,
                         "_type",
                         n00b_json_string_new(k_statement_type_uri));

    // `subject` — array of { name, digest: { alg: hexstr } }
    n00b_json_node_t *subj_arr = n00b_json_array_new();
    size_t            subj_n   = st->subjects.len;

    if (subj_n == 0) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_STMT_MISSING_FIELD);
    }

    for (size_t i = 0; i < subj_n; i++) {
        subject_entry_t *e        = st->subjects.data[i];
        n00b_json_node_t *subj_obj = n00b_json_object_new();
        char *name_cstr = nstr_to_cstr(e->name, alloc_for_call);
        n00b_json_object_put(subj_obj,
                             "name",
                             n00b_json_string_new(name_cstr));
        n00b_json_node_t *digest_obj = n00b_json_object_new();
        for (size_t j = 0; j < e->digest_algs.len; j++) {
            n00b_string_t *alg = e->digest_algs.data[j];
            n00b_string_t *hex = e->digest_hexes.data[j];
            char *alg_cstr = nstr_to_cstr(alg, alloc_for_call);
            char *hex_cstr = nstr_to_cstr(hex, alloc_for_call);
            n00b_json_object_put(digest_obj,
                                 alg_cstr,
                                 n00b_json_string_new(hex_cstr));
        }
        n00b_json_object_put(subj_obj, "digest", digest_obj);
        n00b_json_array_push(subj_arr, subj_obj);
    }
    n00b_json_object_put(root, "subject", subj_arr);

    // `predicateType`
    char *pt_cstr = nstr_to_cstr(st->predicate_type, alloc_for_call);
    n00b_json_object_put(root,
                         "predicateType",
                         n00b_json_string_new(pt_cstr));

    // `predicate` — re-parse the stored bytes and embed the parsed
    // tree so its serialization picks up the same compact form.
    const char       *err = nullptr;
    n00b_json_node_t *pred_node = n00b_json_parse(st->predicate_json->data,
                                                  st->predicate_json->byte_len,
                                                  &err);
    if (pred_node == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_STMT_BAD_JSON);
    }
    n00b_json_object_put(root, "predicate", pred_node);

    char *encoded = n00b_json_encode(root, .pretty = false);
    if (encoded == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_STMT_BAD_JSON);
    }

    size_t enc_len = strlen(encoded);
    n00b_buffer_t *out = n00b_buffer_from_bytes(encoded,
                                                (int64_t)enc_len,
                                                .allocator = alloc_for_call);
    return n00b_result_ok(n00b_buffer_t *, out);
}

// ---------------------------------------------------------------------------
// Parse.
//
// Read a JSON object back into a fresh statement builder. We accept any
// document whose `_type` is the in-toto v1 URI; subjects, predicateType,
// and predicate are required.
// ---------------------------------------------------------------------------

// JSON-object key lookup lives in the shared internal helper:
// `n00b_attest_json_obj_lookup` (declared in
// `include/internal/attest/json_util.h`, defined in
// `src/attest/json_util.c`). Used here and by `dsse.c`.

// Decode a lowercase-hex string into a fresh buffer.
static n00b_buffer_t *
hex_decode_to_buffer(const char *hex, size_t len, n00b_allocator_t *allocator)
{
    if ((len & 1) != 0) {
        return nullptr;
    }
    size_t  out_len = len / 2;
    uint8_t *out    = (uint8_t *)n00b_alloc_array_with_opts(
        char,
        out_len,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    for (size_t i = 0; i < out_len; i++) {
        char hi = hex[i * 2];
        char lo = hex[i * 2 + 1];
        int  hv, lv;
        if      (hi >= '0' && hi <= '9') hv = hi - '0';
        else if (hi >= 'a' && hi <= 'f') hv = hi - 'a' + 10;
        else if (hi >= 'A' && hi <= 'F') hv = hi - 'A' + 10;
        else return nullptr;
        if      (lo >= '0' && lo <= '9') lv = lo - '0';
        else if (lo >= 'a' && lo <= 'f') lv = lo - 'a' + 10;
        else if (lo >= 'A' && lo <= 'F') lv = lo - 'A' + 10;
        else return nullptr;
        out[i] = (uint8_t)((hv << 4) | lv);
    }
    return n00b_buffer_from_bytes((char *)out,
                                  (int64_t)out_len,
                                  .allocator = allocator);
}

n00b_result_t(n00b_attest_statement_t *)
n00b_attest_statement_parse(n00b_buffer_t *bytes) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (bytes == nullptr || bytes->byte_len == 0) {
        return n00b_result_err(n00b_attest_statement_t *,
                               N00B_ATTEST_ERR_STMT_BAD_INPUT);
    }

    const char       *err  = nullptr;
    n00b_json_node_t *root = n00b_json_parse(bytes->data,
                                              bytes->byte_len,
                                              &err);
    if (!n00b_json_is_object(root)) {
        return n00b_result_err(n00b_attest_statement_t *,
                               N00B_ATTEST_ERR_STMT_BAD_JSON);
    }

    // _type must equal the in-toto v1 URI.
    n00b_json_node_t *type_node = n00b_attest_json_obj_lookup(root, r"_type");
    if (!n00b_json_is_string(type_node)) {
        return n00b_result_err(n00b_attest_statement_t *,
                               N00B_ATTEST_ERR_STMT_MISSING_FIELD);
    }
    if (strcmp(n00b_json_as_cstr(type_node), k_statement_type_uri) != 0) {
        return n00b_result_err(n00b_attest_statement_t *,
                               N00B_ATTEST_ERR_STMT_WRONG_TYPE);
    }

    // Build the new builder.
    n00b_attest_statement_t *st = n00b_attest_statement_new(
        .allocator = allocator);

    // subject (array of objects).
    n00b_json_node_t *subj_arr = n00b_attest_json_obj_lookup(root, r"subject");
    if (!n00b_json_is_array(subj_arr)) {
        return n00b_result_err(n00b_attest_statement_t *,
                               N00B_ATTEST_ERR_STMT_MISSING_FIELD);
    }
    size_t subj_n = n00b_json_array_len(subj_arr);
    if (subj_n == 0) {
        return n00b_result_err(n00b_attest_statement_t *,
                               N00B_ATTEST_ERR_STMT_MISSING_FIELD);
    }
    for (size_t i = 0; i < subj_n; i++) {
        n00b_json_node_t *subj_obj = n00b_json_array_get(subj_arr, i);
        if (!n00b_json_is_object(subj_obj)) {
            return n00b_result_err(n00b_attest_statement_t *,
                                   N00B_ATTEST_ERR_STMT_BAD_JSON);
        }
        n00b_json_node_t *name_node = n00b_attest_json_obj_lookup(subj_obj, r"name");
        n00b_json_node_t *dig_node  = n00b_attest_json_obj_lookup(subj_obj, r"digest");
        if (!n00b_json_is_string(name_node) || !n00b_json_is_object(dig_node)) {
            return n00b_result_err(n00b_attest_statement_t *,
                                   N00B_ATTEST_ERR_STMT_BAD_JSON);
        }
        // Walk the digest object: for each key/value, treat the value as
        // a lowercase-hex string and re-feed through _add_subject so the
        // entry is normalized through the canonical builder path.
        n00b_json_object_t *dig_obj = n00b_json_as_object(dig_node);
        if (dig_obj == nullptr) {
            return n00b_result_err(n00b_attest_statement_t *,
                                   N00B_ATTEST_ERR_STMT_BAD_JSON);
        }
        bool first_digest = true;
        n00b_dict_foreach(dig_obj, alg_key, v, {
            const char *alg = alg_key == nullptr ? nullptr : alg_key->data;
            if (alg == nullptr || !n00b_json_is_string(v)) {
                return n00b_result_err(n00b_attest_statement_t *,
                                       N00B_ATTEST_ERR_STMT_BAD_JSON);
            }
            // In the v1 wire shape this WP exercises, the alg is sha256
            // and the value is a 64-char hex string of the 32-byte
            // digest. _add_subject decodes via the same hex-decode path.
            // For now, only sha256 is wired through; non-sha256 algs
            // round-trip on the JSON shape but are not reconstructed
            // into the builder's add_subject call.
            if (strcmp(alg, "sha256") == 0 && first_digest) {
                const char *digest_cstr = n00b_json_as_cstr(v);
                n00b_buffer_t *raw = hex_decode_to_buffer(
                    digest_cstr,
                    strlen(digest_cstr),
                    st->allocator);
                if (raw == nullptr) {
                    return n00b_result_err(n00b_attest_statement_t *,
                                           N00B_ATTEST_ERR_STMT_BAD_JSON);
                }
                n00b_string_t *name_str = n00b_string_from_cstr(
                    n00b_json_as_cstr(name_node),
                    .allocator = st->allocator);
                auto ar = n00b_attest_statement_add_subject(
                    st,
                    .name      = name_str,
                    .digest    = raw,
                    .allocator = st->allocator);
                if (n00b_result_is_err(ar)) {
                    return n00b_result_err(n00b_attest_statement_t *,
                                           n00b_result_get_err(ar));
                }
                first_digest = false;
            }
        });
    }

    // predicateType.
    n00b_json_node_t *pt_node = n00b_attest_json_obj_lookup(root, r"predicateType");
    if (!n00b_json_is_string(pt_node)) {
        return n00b_result_err(n00b_attest_statement_t *,
                               N00B_ATTEST_ERR_STMT_MISSING_FIELD);
    }
    n00b_string_t *pt_str = n00b_string_from_cstr(n00b_json_as_cstr(pt_node),
                                                  .allocator = st->allocator);
    auto sr = n00b_attest_statement_set_predicate_type(st,
                                                       pt_str,
                                                       .allocator = st->allocator);
    if (n00b_result_is_err(sr)) {
        return n00b_result_err(n00b_attest_statement_t *,
                               n00b_result_get_err(sr));
    }

    // predicate — serialize the parsed sub-tree back to JSON bytes and
    // hand those to _set_predicate_json so the round-trip is closed
    // through the canonical entry point.
    n00b_json_node_t *pred_node = n00b_attest_json_obj_lookup(root, r"predicate");
    if (pred_node == nullptr) {
        return n00b_result_err(n00b_attest_statement_t *,
                               N00B_ATTEST_ERR_STMT_MISSING_FIELD);
    }
    char *pred_enc = n00b_json_encode(pred_node, .pretty = false);
    if (pred_enc == nullptr) {
        return n00b_result_err(n00b_attest_statement_t *,
                               N00B_ATTEST_ERR_STMT_BAD_JSON);
    }
    n00b_buffer_t *pred_buf = n00b_buffer_from_bytes(pred_enc,
                                                     (int64_t)strlen(pred_enc),
                                                     .allocator = st->allocator);
    auto pr = n00b_attest_statement_set_predicate_json(
        st,
        pred_buf,
        .allocator = st->allocator);
    if (n00b_result_is_err(pr)) {
        return n00b_result_err(n00b_attest_statement_t *,
                               n00b_result_get_err(pr));
    }

    return n00b_result_ok(n00b_attest_statement_t *, st);
}

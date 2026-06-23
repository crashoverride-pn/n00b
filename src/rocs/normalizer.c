#include "rocs/normalizer.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/hash.h"
#include "text/strings/string_ops.h"
#include "text/unicode/casemap.h"

typedef struct {
    n00b_string_t    *key;
    n00b_json_node_t *value;
} rocs_norm_kv_t;

static_assert(sizeof(double) == 8);

typedef enum {
    ROCS_NORM_TAG_NULL   = 1,
    ROCS_NORM_TAG_BOOL   = 2,
    ROCS_NORM_TAG_INT    = 3,
    ROCS_NORM_TAG_DOUBLE = 4,
    ROCS_NORM_TAG_STRING = 5,
} rocs_norm_scalar_tag_t;

#define ROCS_NORM_HASH_STACK_FRAME_MAX 4096

static n00b_string_t *
rocs_norm_root_path(n00b_string_t *path)
{
    return path == nullptr ? r"" : path;
}

static bool
rocs_norm_index_kind_known(n00b_store_index_kind_t kind)
{
    switch (kind) {
    case N00B_STORE_INDEX_TERM:
    case N00B_STORE_INDEX_FULLTEXT:
    case N00B_STORE_INDEX_NGRAM:
    case N00B_STORE_INDEX_NUMERIC:
    case N00B_STORE_INDEX_BOOL:
    case N00B_STORE_INDEX_VECTOR:
        return true;
    case N00B_STORE_INDEX_NONE:
        return false;
    }
    return false;
}

static n00b_buffer_t *
rocs_norm_buffer_new(uint64_t len) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (len > (uint64_t)INT64_MAX) {
        return nullptr;
    }

    n00b_buffer_t *buf = n00b_alloc_with_opts(
        n00b_buffer_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    n00b_buffer_init(buf,
                     .length    = (int64_t)len,
                     .allocator = allocator,
                     .no_lock   = true);
    return buf;
}

static void
rocs_norm_write_be64(uint8_t *dst, uint64_t value)
{
    for (uint8_t i = 0; i < 8; i++) {
        dst[i] = (uint8_t)((value >> (56 - (i * 8))) & 0xffu);
    }
}

static bool
rocs_norm_f64_nonfinite(uint64_t bits)
{
    return (bits & UINT64_C(0x7ff0000000000000))
           == UINT64_C(0x7ff0000000000000);
}

static n00b_result_t(n00b_buffer_t *)
rocs_norm_payload(n00b_json_node_t *node) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (node == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_STORE_NORM_ERR_ARG);
    }

    n00b_json_type_t variant_tag = n00b_json_type(node);
    switch (variant_tag) {
    case N00B_JSON_NULL: {
        n00b_buffer_t *buf = rocs_norm_buffer_new(0, .allocator = allocator);
        if (buf == nullptr) {
            return n00b_result_err(n00b_buffer_t *, N00B_STORE_NORM_ERR_ARG);
        }
        return n00b_result_ok(n00b_buffer_t *, buf);
    }

    case N00B_JSON_BOOL: {
        n00b_buffer_t *buf = rocs_norm_buffer_new(1, .allocator = allocator);
        if (buf == nullptr) {
            return n00b_result_err(n00b_buffer_t *, N00B_STORE_NORM_ERR_ARG);
        }
        buf->data[0] = n00b_json_as_bool(node) ? 1 : 0;
        return n00b_result_ok(n00b_buffer_t *, buf);
    }

    case N00B_JSON_INT: {
        n00b_buffer_t *buf = rocs_norm_buffer_new(8, .allocator = allocator);
        if (buf == nullptr) {
            return n00b_result_err(n00b_buffer_t *, N00B_STORE_NORM_ERR_ARG);
        }
        rocs_norm_write_be64((uint8_t *)buf->data,
                             (uint64_t)n00b_json_as_i64(node));
        return n00b_result_ok(n00b_buffer_t *, buf);
    }

    case N00B_JSON_DOUBLE: {
        n00b_buffer_t *buf = rocs_norm_buffer_new(8, .allocator = allocator);
        if (buf == nullptr) {
            return n00b_result_err(n00b_buffer_t *, N00B_STORE_NORM_ERR_ARG);
        }
        union [[n00b::raw_union]] {
            double   f;
            uint64_t u;
        } bits = {
            .f = n00b_json_as_f64(node),
        };

        if (rocs_norm_f64_nonfinite(bits.u)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_STORE_NORM_ERR_NUMERIC);
        }
        if ((bits.u & UINT64_C(0x7fffffffffffffff)) == 0) {
            bits.u = 0;
        }
        rocs_norm_write_be64((uint8_t *)buf->data, bits.u);
        return n00b_result_ok(n00b_buffer_t *, buf);
    }

    case N00B_JSON_STRING: {
        n00b_string_t *s = n00b_json_as_string(node);
        if (s == nullptr || (s->u8_bytes != 0 && s->data == nullptr)) {
            return n00b_result_err(n00b_buffer_t *, N00B_STORE_NORM_ERR_STATE);
        }
        if (s->u8_bytes > (size_t)INT64_MAX) {
            return n00b_result_err(n00b_buffer_t *, N00B_STORE_NORM_ERR_ARG);
        }
        return n00b_result_ok(n00b_buffer_t *,
                              n00b_buffer_from_bytes(s->data,
                                                     (int64_t)s->u8_bytes,
                                                     .allocator = allocator));
    }

    case N00B_JSON_ARRAY:
    case N00B_JSON_OBJECT:
        return n00b_result_err(n00b_buffer_t *, N00B_STORE_NORM_ERR_TYPE);
    }

    return n00b_result_err(n00b_buffer_t *, N00B_STORE_NORM_ERR_TYPE);
}

static bool
rocs_norm_scalar_tag(n00b_json_node_t *node, uint8_t *tag)
{
    if (node == nullptr || tag == nullptr) {
        return false;
    }

    switch (n00b_json_type(node)) {
    case N00B_JSON_NULL:
        *tag = ROCS_NORM_TAG_NULL;
        return true;

    case N00B_JSON_BOOL:
        *tag = ROCS_NORM_TAG_BOOL;
        return true;

    case N00B_JSON_INT:
        *tag = ROCS_NORM_TAG_INT;
        return true;

    case N00B_JSON_DOUBLE:
        *tag = ROCS_NORM_TAG_DOUBLE;
        return true;

    case N00B_JSON_STRING:
        *tag = ROCS_NORM_TAG_STRING;
        return true;

    case N00B_JSON_ARRAY:
    case N00B_JSON_OBJECT:
        return false;
    }

    return false;
}

static n00b_store_normalized_t *
rocs_norm_term_new(n00b_string_t    *path,
                   n00b_json_node_t *value,
                   n00b_buffer_t    *bytes) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_store_normalized_t *term = n00b_alloc_with_opts(
        n00b_store_normalized_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    term->path  = rocs_norm_root_path(path);
    term->value = value;
    term->bytes = bytes;
    return term;
}

static n00b_store_normalized_list_t *
rocs_norm_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_store_normalized_list_t *items = n00b_alloc_with_opts(
        n00b_store_normalized_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *items = n00b_list_new_private(n00b_store_normalized_t *,
                                   .allocator = allocator,
                                   .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return items;
}

static bool
rocs_norm_text_base_token_byte(uint8_t byte)
{
    if (byte >= 'a' && byte <= 'z') {
        return true;
    }
    if (byte >= 'A' && byte <= 'Z') {
        return true;
    }
    if (byte >= '0' && byte <= '9') {
        return true;
    }
    if (byte == '_') {
        return true;
    }
    return byte >= 0x80;
}

static bool
rocs_norm_text_connector_byte(uint8_t byte)
{
    return byte == '-' || byte == ':';
}

static bool
rocs_norm_ngram_n_valid(uint8_t ngram_n)
{
    return ngram_n >= N00B_STORE_NGRAM_MIN_N
        && ngram_n <= N00B_STORE_NGRAM_MAX_N;
}

static uint64_t
rocs_norm_text_token_end(n00b_string_t *folded, uint64_t start)
{
    if (folded == nullptr || start >= (uint64_t)folded->u8_bytes
        || !rocs_norm_text_base_token_byte((uint8_t)folded->data[start])) {
        return start;
    }

    uint64_t folded_len = (uint64_t)folded->u8_bytes;
    uint64_t i          = start + 1;
    while (i < folded_len) {
        uint8_t byte = (uint8_t)folded->data[i];
        if (rocs_norm_text_base_token_byte(byte)) {
            i++;
            continue;
        }
        if (rocs_norm_text_connector_byte(byte)) {
            uint64_t connector_start = i;
            while (i < folded_len
                   && rocs_norm_text_connector_byte((uint8_t)folded->data[i])) {
                i++;
            }
            if (i < folded_len
                && rocs_norm_text_base_token_byte((uint8_t)folded->data[i])) {
                i++;
                continue;
            }
            i = connector_start;
        }
        break;
    }

    return i;
}

static bool
rocs_norm_text_full_value_needed(n00b_string_t *folded)
{
    if (folded == nullptr || folded->data == nullptr || folded->u8_bytes == 0) {
        return false;
    }

    uint64_t folded_len = (uint64_t)folded->u8_bytes;
    uint64_t first      = folded_len;
    for (uint64_t i = 0; i < folded_len; i++) {
        if (rocs_norm_text_base_token_byte((uint8_t)folded->data[i])) {
            first = i;
            break;
        }
    }
    if (first == folded_len) {
        return false;
    }

    return first != 0 || rocs_norm_text_token_end(folded, 0) != folded_len;
}

static n00b_result_t(bool)
rocs_norm_text_term_add(n00b_store_normalized_list_t *out,
                        n00b_string_t                *path,
                        n00b_string_t                *folded,
                        uint64_t                      start,
                        uint64_t                      len) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (out == nullptr || folded == nullptr || len == 0
        || start > (uint64_t)folded->u8_bytes
        || len > (uint64_t)folded->u8_bytes - start
        || len > (uint64_t)INT64_MAX) {
        return n00b_result_err(bool, N00B_STORE_NORM_ERR_ARG);
    }

    n00b_string_t *token =
        n00b_string_from_raw(folded->data + start,
                             (int64_t)len,
                             .allocator = allocator);
    if (token == nullptr || (token->u8_bytes != 0 && token->data == nullptr)) {
        return n00b_result_err(bool, N00B_STORE_NORM_ERR_STATE);
    }

    n00b_json_node_t *value =
        n00b_json_string_new_from_n00b(token, .allocator = allocator);
    n00b_buffer_t *bytes =
        n00b_buffer_from_bytes(token->data,
                               (int64_t)token->u8_bytes,
                               .allocator = allocator);
    if (value == nullptr || bytes == nullptr) {
        return n00b_result_err(bool, N00B_STORE_NORM_ERR_STATE);
    }

    n00b_store_normalized_t *term =
        rocs_norm_term_new(path, value, bytes, .allocator = allocator);
    n00b_list_push(*out, term);
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_norm_list_add_scalar(n00b_store_normalized_list_t *out,
                          n00b_json_node_t             *node,
                          n00b_string_t                *path) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto scalar_r = n00b_store_normalize_scalar(node,
                                                .path      = path,
                                                .allocator = allocator);
    if (n00b_result_is_err(scalar_r)) {
        return n00b_result_err(bool, n00b_result_get_err(scalar_r));
    }

    n00b_store_normalized_t *term = n00b_result_get(scalar_r);
    n00b_list_push(*out, term);
    return n00b_result_ok(bool, true);
}

static uint64_t
rocs_norm_escaped_key_len(n00b_string_t *key)
{
    uint64_t result = 0;
    if (key == nullptr) {
        return 0;
    }

    for (size_t i = 0; i < key->u8_bytes; i++) {
        char ch = key->data[i];
        result += (ch == '~' || ch == '/') ? 2 : 1;
    }
    return result;
}

static uint8_t
rocs_norm_decimal_len(uint64_t value)
{
    uint8_t len = 1;
    while (value >= 10) {
        value /= 10;
        len++;
    }
    return len;
}

static n00b_string_t *
rocs_norm_path_key(n00b_string_t *parent,
                   n00b_string_t *key) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    parent = rocs_norm_root_path(parent);
    if (key == nullptr || (key->u8_bytes != 0 && key->data == nullptr)) {
        return nullptr;
    }

    uint64_t escaped = rocs_norm_escaped_key_len(key);
    uint64_t plen    = (uint64_t)parent->u8_bytes;
    if (plen > (uint64_t)INT64_MAX || escaped > (uint64_t)INT64_MAX
        || UINT64_MAX - plen < escaped + 1) {
        return nullptr;
    }

    uint64_t total = plen + 1 + escaped;
    if (total > (uint64_t)INT64_MAX) {
        return nullptr;
    }

    char *data = n00b_alloc_array_with_opts(char,
                                            total == 0 ? 1 : total,
                                            &(n00b_alloc_opts_t){
                                                .allocator = allocator,
                                                .scan_kind = N00B_GC_SCAN_KIND_NONE,
                                            });
    uint64_t pos = 0;
    for (size_t i = 0; i < parent->u8_bytes; i++) {
        data[pos++] = parent->data[i];
    }
    data[pos++] = '/';
    for (size_t i = 0; i < key->u8_bytes; i++) {
        char ch = key->data[i];
        if (ch == '~') {
            data[pos++] = '~';
            data[pos++] = '0';
        }
        else if (ch == '/') {
            data[pos++] = '~';
            data[pos++] = '1';
        }
        else {
            data[pos++] = ch;
        }
    }

    return n00b_string_from_raw(data, (int64_t)total, .allocator = allocator);
}

static n00b_string_t *
rocs_norm_path_index(n00b_string_t    *parent,
                     uint64_t          index) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    parent = rocs_norm_root_path(parent);

    uint64_t plen   = (uint64_t)parent->u8_bytes;
    uint8_t  digits = rocs_norm_decimal_len(index);
    if (plen > (uint64_t)INT64_MAX || UINT64_MAX - plen < (uint64_t)digits + 1) {
        return nullptr;
    }

    uint64_t total = plen + 1 + digits;
    if (total > (uint64_t)INT64_MAX) {
        return nullptr;
    }

    char *data = n00b_alloc_array_with_opts(char,
                                            total == 0 ? 1 : total,
                                            &(n00b_alloc_opts_t){
                                                .allocator = allocator,
                                                .scan_kind = N00B_GC_SCAN_KIND_NONE,
                                            });
    uint64_t pos = 0;
    for (size_t i = 0; i < parent->u8_bytes; i++) {
        data[pos++] = parent->data[i];
    }
    data[pos++] = '/';

    uint64_t divisor = 1;
    for (uint8_t i = 1; i < digits; i++) {
        divisor *= 10;
    }
    while (divisor != 0) {
        data[pos++] = (char)('0' + ((index / divisor) % 10));
        divisor /= 10;
    }

    return n00b_string_from_raw(data, (int64_t)total, .allocator = allocator);
}

static n00b_result_t(bool)
rocs_norm_walk(n00b_store_normalized_list_t *out,
               n00b_json_node_t             *node,
               n00b_string_t                *path) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

static void
rocs_norm_sort_pairs(rocs_norm_kv_t *pairs, size_t n)
{
    for (size_t i = 1; i < n; i++) {
        rocs_norm_kv_t cur = pairs[i];
        size_t         j   = i;

        while (j > 0 && n00b_unicode_str_cmp(pairs[j - 1].key, cur.key) > 0) {
            pairs[j] = pairs[j - 1];
            j--;
        }
        pairs[j] = cur;
    }
}

static n00b_result_t(bool)
rocs_norm_walk(n00b_store_normalized_list_t *out,
               n00b_json_node_t             *node,
               n00b_string_t                *path) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (node == nullptr || out == nullptr) {
        return n00b_result_err(bool, N00B_STORE_NORM_ERR_ARG);
    }

    switch (n00b_json_type(node)) {
    case N00B_JSON_NULL:
    case N00B_JSON_BOOL:
    case N00B_JSON_INT:
    case N00B_JSON_DOUBLE:
    case N00B_JSON_STRING:
        return rocs_norm_list_add_scalar(out,
                                         node,
                                         path,
                                         .allocator = allocator);

    case N00B_JSON_ARRAY: {
        uint64_t len = (uint64_t)n00b_json_array_len(node);
        for (uint64_t i = 0; i < len; i++) {
            n00b_string_t *child_path =
                rocs_norm_path_index(path, i, .allocator = allocator);
            if (child_path == nullptr) {
                return n00b_result_err(bool, N00B_STORE_NORM_ERR_ARG);
            }
            n00b_json_node_t *child = n00b_json_array_get(node, (size_t)i);
            auto child_r =
                rocs_norm_walk(out, child, child_path, .allocator = allocator);
            if (n00b_result_is_err(child_r)) {
                return child_r;
            }
        }
        return n00b_result_ok(bool, true);
    }

    case N00B_JSON_OBJECT: {
        auto entries_r = n00b_json_object_entries(node, .allocator = allocator);
        if (n00b_result_is_err(entries_r)) {
            n00b_err_t err = n00b_result_get_err(entries_r);
            return n00b_result_err(bool,
                                   err == N00B_JSON_ERR_TYPE
                                       ? N00B_STORE_NORM_ERR_TYPE
                                       : N00B_STORE_NORM_ERR_STATE);
        }

        n00b_json_object_entry_list_t *entries = n00b_result_get(entries_r);
        size_t cap = entries == nullptr ? 0 : n00b_list_len(*entries);
        if (cap == 0) {
            return n00b_result_ok(bool, true);
        }

        rocs_norm_kv_t *pairs = n00b_alloc_array_with_opts(
            rocs_norm_kv_t,
            cap,
            &(n00b_alloc_opts_t){
                .allocator = allocator,
            });
        size_t live = 0;
        for (size_t i = 0; i < cap; i++) {
            n00b_json_object_entry_t *entry = n00b_list_get(*entries, i);
            if (entry == nullptr || entry->key == nullptr
                || entry->value == nullptr) {
                return n00b_result_err(bool, N00B_STORE_NORM_ERR_STATE);
            }
            pairs[live].key   = entry->key;
            pairs[live].value = entry->value;
            live++;
        }

        rocs_norm_sort_pairs(pairs, live);
        for (size_t i = 0; i < live; i++) {
            n00b_string_t *child_path =
                rocs_norm_path_key(path, pairs[i].key, .allocator = allocator);
            if (child_path == nullptr) {
                return n00b_result_err(bool, N00B_STORE_NORM_ERR_ARG);
            }

            auto child_r = rocs_norm_walk(out,
                                          pairs[i].value,
                                          child_path,
                                          .allocator = allocator);
            if (n00b_result_is_err(child_r)) {
                return child_r;
            }
        }
        return n00b_result_ok(bool, true);
    }
    }

    return n00b_result_err(bool, N00B_STORE_NORM_ERR_TYPE);
}

n00b_string_t *
n00b_store_normalize_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_STORE_NORM_OK:          return r"OK";
    case N00B_STORE_NORM_ERR_ARG:     return r"ARG";
    case N00B_STORE_NORM_ERR_TYPE:    return r"TYPE";
    case N00B_STORE_NORM_ERR_NUMERIC: return r"NUMERIC";
    case N00B_STORE_NORM_ERR_STATE:   return r"STATE";
    }
    return r"UNKNOWN";
}

n00b_result_t(n00b_store_normalized_t *)
n00b_store_normalize_scalar(n00b_json_node_t *node) _kargs
{
    n00b_string_t    *path      = nullptr;
    n00b_allocator_t *allocator = nullptr;
}
{
    if (node == nullptr) {
        return n00b_result_err(n00b_store_normalized_t *,
                               N00B_STORE_NORM_ERR_ARG);
    }

    auto payload_r = rocs_norm_payload(node, .allocator = allocator);
    if (n00b_result_is_err(payload_r)) {
        return n00b_result_err(n00b_store_normalized_t *,
                               n00b_result_get_err(payload_r));
    }

    n00b_store_normalized_t *term =
        rocs_norm_term_new(rocs_norm_root_path(path),
                           node,
                           n00b_result_get(payload_r),
                           .allocator = allocator);

    return n00b_result_ok(n00b_store_normalized_t *, term);
}

n00b_result_t(n00b_store_normalized_list_t *)
n00b_store_normalize_json(n00b_json_node_t *node) _kargs
{
    n00b_string_t    *root_path = nullptr;
    n00b_allocator_t *allocator = nullptr;
}
{
    if (node == nullptr) {
        return n00b_result_err(n00b_store_normalized_list_t *,
                               N00B_STORE_NORM_ERR_ARG);
    }

    n00b_store_normalized_list_t *out =
        rocs_norm_list_new(.allocator = allocator);
    auto walk_r = rocs_norm_walk(out,
                                 node,
                                 rocs_norm_root_path(root_path),
                                 .allocator = allocator);
    if (n00b_result_is_err(walk_r)) {
        return n00b_result_err(n00b_store_normalized_list_t *,
                               n00b_result_get_err(walk_r));
    }

    return n00b_result_ok(n00b_store_normalized_list_t *, out);
}

n00b_result_t(n00b_store_normalized_list_t *)
n00b_store_normalize_text_tokens(n00b_json_node_t *node) _kargs
{
    n00b_string_t    *path               = nullptr;
    bool              include_full_value = true;
    n00b_allocator_t *allocator          = nullptr;
}
{
    if (node == nullptr) {
        return n00b_result_err(n00b_store_normalized_list_t *,
                               N00B_STORE_NORM_ERR_ARG);
    }
    if (!n00b_json_is_string(node)) {
        return n00b_result_err(n00b_store_normalized_list_t *,
                               N00B_STORE_NORM_ERR_TYPE);
    }

    n00b_string_t *raw = n00b_json_as_string(node);
    if (raw == nullptr || (raw->u8_bytes != 0 && raw->data == nullptr)) {
        return n00b_result_err(n00b_store_normalized_list_t *,
                               N00B_STORE_NORM_ERR_STATE);
    }
    if (raw->u8_bytes > (size_t)INT64_MAX) {
        return n00b_result_err(n00b_store_normalized_list_t *,
                               N00B_STORE_NORM_ERR_ARG);
    }

    n00b_store_normalized_list_t *out =
        rocs_norm_list_new(.allocator = allocator);
    n00b_string_t *folded = n00b_unicode_casefold(raw,
                                                  .allocator = allocator);
    if (folded == nullptr
        || (folded->u8_bytes != 0 && folded->data == nullptr)) {
        return n00b_result_err(n00b_store_normalized_list_t *,
                               N00B_STORE_NORM_ERR_STATE);
    }

    uint64_t folded_len = (uint64_t)folded->u8_bytes;
    if (include_full_value && rocs_norm_text_full_value_needed(folded)) {
        auto add_r = rocs_norm_text_term_add(
            out,
            rocs_norm_root_path(path),
            folded,
            0,
            folded_len,
            .allocator = allocator);
        if (n00b_result_is_err(add_r)) {
            return n00b_result_err(n00b_store_normalized_list_t *,
                                   n00b_result_get_err(add_r));
        }
    }

    uint64_t i          = 0;
    while (i < folded_len) {
        while (i < folded_len
               && !rocs_norm_text_base_token_byte((uint8_t)folded->data[i])) {
            i++;
        }
        if (i >= folded_len) {
            break;
        }

        uint64_t start = i;
        i = rocs_norm_text_token_end(folded, start);

        auto add_r = rocs_norm_text_term_add(
            out,
            rocs_norm_root_path(path),
            folded,
            start,
            i - start,
            .allocator = allocator);
        if (n00b_result_is_err(add_r)) {
            return n00b_result_err(n00b_store_normalized_list_t *,
                                   n00b_result_get_err(add_r));
        }
    }

    return n00b_result_ok(n00b_store_normalized_list_t *, out);
}

n00b_result_t(n00b_store_normalized_list_t *)
n00b_store_normalize_text_ngrams(n00b_json_node_t *node) _kargs
{
    n00b_string_t    *path      = nullptr;
    uint8_t           ngram_n   = N00B_STORE_NGRAM_DEFAULT_N;
    n00b_allocator_t *allocator = nullptr;
}
{
    if (node == nullptr) {
        return n00b_result_err(n00b_store_normalized_list_t *,
                               N00B_STORE_NORM_ERR_ARG);
    }
    if (!rocs_norm_ngram_n_valid(ngram_n)) {
        return n00b_result_err(n00b_store_normalized_list_t *,
                               N00B_STORE_NORM_ERR_ARG);
    }
    if (!n00b_json_is_string(node)) {
        return n00b_result_err(n00b_store_normalized_list_t *,
                               N00B_STORE_NORM_ERR_TYPE);
    }

    n00b_string_t *raw = n00b_json_as_string(node);
    if (raw == nullptr || (raw->u8_bytes != 0 && raw->data == nullptr)) {
        return n00b_result_err(n00b_store_normalized_list_t *,
                               N00B_STORE_NORM_ERR_STATE);
    }
    if (raw->u8_bytes > (size_t)INT64_MAX) {
        return n00b_result_err(n00b_store_normalized_list_t *,
                               N00B_STORE_NORM_ERR_ARG);
    }

    n00b_store_normalized_list_t *out =
        rocs_norm_list_new(.allocator = allocator);
    n00b_string_t *folded = n00b_unicode_casefold(raw,
                                                  .allocator = allocator);
    if (folded == nullptr
        || (folded->u8_bytes != 0 && folded->data == nullptr)) {
        return n00b_result_err(n00b_store_normalized_list_t *,
                               N00B_STORE_NORM_ERR_STATE);
    }
    if (folded->u8_bytes > (size_t)INT64_MAX) {
        return n00b_result_err(n00b_store_normalized_list_t *,
                               N00B_STORE_NORM_ERR_ARG);
    }

    uint64_t folded_len = (uint64_t)folded->u8_bytes;
    uint64_t gram_len   = (uint64_t)ngram_n;
    if (folded_len < gram_len) {
        return n00b_result_ok(n00b_store_normalized_list_t *, out);
    }

    for (uint64_t i = 0; i <= folded_len - gram_len; i++) {
        auto add_r = rocs_norm_text_term_add(
            out,
            rocs_norm_root_path(path),
            folded,
            i,
            gram_len,
            .allocator = allocator);
        if (n00b_result_is_err(add_r)) {
            return n00b_result_err(n00b_store_normalized_list_t *,
                                   n00b_result_get_err(add_r));
        }
    }

    return n00b_result_ok(n00b_store_normalized_list_t *, out);
}

static n00b_result_t(n00b_uint128_t)
rocs_norm_hash_bytes(n00b_store_index_kind_t  kind,
                     uint8_t                  scalar_tag,
                     n00b_string_t           *raw_path,
                     const char              *payload,
                     uint64_t                 payload_len) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!rocs_norm_index_kind_known(kind)) {
        return n00b_result_err(n00b_uint128_t, N00B_STORE_NORM_ERR_ARG);
    }

    n00b_string_t *path = rocs_norm_root_path(raw_path);
    if (path == nullptr) {
        return n00b_result_err(n00b_uint128_t, N00B_STORE_NORM_ERR_ARG);
    }
    if (path->u8_bytes != 0 && path->data == nullptr) {
        return n00b_result_err(n00b_uint128_t, N00B_STORE_NORM_ERR_STATE);
    }
    if (payload_len != 0 && payload == nullptr) {
        return n00b_result_err(n00b_uint128_t, N00B_STORE_NORM_ERR_STATE);
    }

    uint64_t path_len = (uint64_t)path->u8_bytes;
    if (path_len > (uint64_t)INT64_MAX
        || payload_len > (uint64_t)INT64_MAX
        || UINT64_MAX - path_len < payload_len
        || path_len + payload_len > UINT64_MAX - 24
        || path_len + payload_len + 24 > (uint64_t)INT64_MAX
        || path_len + payload_len + 24 > (uint64_t)SIZE_MAX) {
        return n00b_result_err(n00b_uint128_t, N00B_STORE_NORM_ERR_ARG);
    }

    uint64_t body_len  = path_len + payload_len;
    uint64_t frame_len = body_len + 24;
    char     stack_frame[ROCS_NORM_HASH_STACK_FRAME_MAX];
    char    *frame_data = stack_frame;

    n00b_buffer_t *heap_frame = nullptr;
    if (frame_len > (uint64_t)sizeof(stack_frame)) {
        heap_frame = rocs_norm_buffer_new(frame_len, .allocator = allocator);
        if (heap_frame == nullptr || heap_frame->data == nullptr) {
            return n00b_result_err(n00b_uint128_t, N00B_STORE_NORM_ERR_ARG);
        }
        frame_data = heap_frame->data;
    }

    frame_data[0] = 'R';
    frame_data[1] = 'N';
    frame_data[2] = 'H';
    frame_data[3] = '1';
    frame_data[4] = (char)kind;
    frame_data[5] = (char)scalar_tag;
    frame_data[6] = 0;
    frame_data[7] = 0;
    rocs_norm_write_be64((uint8_t *)frame_data + 8, path_len);
    rocs_norm_write_be64((uint8_t *)frame_data + 16, payload_len);

    if (path_len != 0) {
        memcpy(frame_data + 24, path->data, (size_t)path_len);
    }
    if (payload_len != 0) {
        memcpy(frame_data + 24 + path_len, payload, (size_t)payload_len);
    }

    n00b_uint128_t hv = n00b_hash_raw(frame_data, (size_t)frame_len);
    if (hv == (n00b_uint128_t)0) {
        hv = (((n00b_uint128_t)UINT64_C(0x726f63736e680001)) << 64)
             | (n00b_uint128_t)UINT64_C(0x686173682d6b6579);
    }

    return n00b_result_ok(n00b_uint128_t, hv);
}

static n00b_result_t(bool)
rocs_norm_visit_string_key(n00b_store_index_kind_t              kind,
                           n00b_string_t                      *path,
                           n00b_string_t                      *folded,
                           uint64_t                            start,
                           uint64_t                            len,
                           n00b_store_normalized_key_visitor_t visitor,
                           void                               *visitor_ctx,
                           n00b_allocator_t                   *allocator)
{
    if (folded == nullptr || visitor == nullptr || len == 0
        || start > (uint64_t)folded->u8_bytes
        || len > (uint64_t)folded->u8_bytes - start) {
        return n00b_result_err(bool, N00B_STORE_NORM_ERR_ARG);
    }

    auto key_r = rocs_norm_hash_bytes(kind,
                                      ROCS_NORM_TAG_STRING,
                                      rocs_norm_root_path(path),
                                      folded->data + start,
                                      len,
                                      .allocator = allocator);
    if (n00b_result_is_err(key_r)) {
        return n00b_result_err(bool, n00b_result_get_err(key_r));
    }
    if (!visitor(visitor_ctx, n00b_result_get(key_r))) {
        return n00b_result_err(bool, N00B_STORE_NORM_ERR_STATE);
    }
    return n00b_result_ok(bool, true);
}

n00b_result_t(uint64_t)
n00b_store_normalize_text_token_keys(
    n00b_json_node_t                     *node,
    n00b_store_normalized_key_visitor_t   visitor,
    void                                *visitor_ctx) _kargs
{
    n00b_string_t    *path               = nullptr;
    bool              include_full_value = true;
    n00b_allocator_t *allocator          = nullptr;
}
{
    if (node == nullptr || visitor == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_NORM_ERR_ARG);
    }
    if (!n00b_json_is_string(node)) {
        return n00b_result_err(uint64_t, N00B_STORE_NORM_ERR_TYPE);
    }

    n00b_string_t *raw = n00b_json_as_string(node);
    if (raw == nullptr || (raw->u8_bytes != 0 && raw->data == nullptr)) {
        return n00b_result_err(uint64_t, N00B_STORE_NORM_ERR_STATE);
    }
    if (raw->u8_bytes > (size_t)INT64_MAX) {
        return n00b_result_err(uint64_t, N00B_STORE_NORM_ERR_ARG);
    }

    n00b_string_t *folded = n00b_unicode_casefold(raw,
                                                  .allocator = allocator);
    if (folded == nullptr
        || (folded->u8_bytes != 0 && folded->data == nullptr)) {
        return n00b_result_err(uint64_t, N00B_STORE_NORM_ERR_STATE);
    }

    uint64_t count      = 0;
    uint64_t folded_len = (uint64_t)folded->u8_bytes;
    if (include_full_value && rocs_norm_text_full_value_needed(folded)) {
        auto visit_r = rocs_norm_visit_string_key(
            N00B_STORE_INDEX_FULLTEXT,
            path,
            folded,
            0,
            folded_len,
            visitor,
            visitor_ctx,
            allocator);
        if (n00b_result_is_err(visit_r)) {
            return n00b_result_err(uint64_t, n00b_result_get_err(visit_r));
        }
        count++;
    }

    uint64_t i          = 0;
    while (i < folded_len) {
        while (i < folded_len
               && !rocs_norm_text_base_token_byte((uint8_t)folded->data[i])) {
            i++;
        }
        if (i >= folded_len) {
            break;
        }

        uint64_t start = i;
        i = rocs_norm_text_token_end(folded, start);

        auto visit_r = rocs_norm_visit_string_key(
            N00B_STORE_INDEX_FULLTEXT,
            path,
            folded,
            start,
            i - start,
            visitor,
            visitor_ctx,
            allocator);
        if (n00b_result_is_err(visit_r)) {
            return n00b_result_err(uint64_t, n00b_result_get_err(visit_r));
        }
        count++;
    }

    return n00b_result_ok(uint64_t, count);
}

n00b_result_t(uint64_t)
n00b_store_normalize_text_ngram_keys(
    n00b_json_node_t                     *node,
    n00b_store_normalized_key_visitor_t   visitor,
    void                                *visitor_ctx) _kargs
{
    n00b_string_t    *path      = nullptr;
    uint8_t           ngram_n   = N00B_STORE_NGRAM_DEFAULT_N;
    n00b_allocator_t *allocator = nullptr;
}
{
    if (node == nullptr || visitor == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_NORM_ERR_ARG);
    }
    if (!rocs_norm_ngram_n_valid(ngram_n)) {
        return n00b_result_err(uint64_t, N00B_STORE_NORM_ERR_ARG);
    }
    if (!n00b_json_is_string(node)) {
        return n00b_result_err(uint64_t, N00B_STORE_NORM_ERR_TYPE);
    }

    n00b_string_t *raw = n00b_json_as_string(node);
    if (raw == nullptr || (raw->u8_bytes != 0 && raw->data == nullptr)) {
        return n00b_result_err(uint64_t, N00B_STORE_NORM_ERR_STATE);
    }
    if (raw->u8_bytes > (size_t)INT64_MAX) {
        return n00b_result_err(uint64_t, N00B_STORE_NORM_ERR_ARG);
    }

    n00b_string_t *folded = n00b_unicode_casefold(raw,
                                                  .allocator = allocator);
    if (folded == nullptr
        || (folded->u8_bytes != 0 && folded->data == nullptr)) {
        return n00b_result_err(uint64_t, N00B_STORE_NORM_ERR_STATE);
    }
    if (folded->u8_bytes > (size_t)INT64_MAX) {
        return n00b_result_err(uint64_t, N00B_STORE_NORM_ERR_ARG);
    }

    uint64_t folded_len = (uint64_t)folded->u8_bytes;
    uint64_t gram_len   = (uint64_t)ngram_n;
    if (folded_len < gram_len) {
        return n00b_result_ok(uint64_t, 0);
    }

    uint64_t count = 0;
    for (uint64_t i = 0; i <= folded_len - gram_len; i++) {
        auto visit_r = rocs_norm_visit_string_key(
            N00B_STORE_INDEX_NGRAM,
            path,
            folded,
            i,
            gram_len,
            visitor,
            visitor_ctx,
            allocator);
        if (n00b_result_is_err(visit_r)) {
            return n00b_result_err(uint64_t, n00b_result_get_err(visit_r));
        }
        count++;
    }

    return n00b_result_ok(uint64_t, count);
}

n00b_result_t(n00b_uint128_t)
n00b_store_normalize_hash(n00b_store_index_kind_t  kind,
                          n00b_store_normalized_t *value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!rocs_norm_index_kind_known(kind)) {
        return n00b_result_err(n00b_uint128_t, N00B_STORE_NORM_ERR_ARG);
    }
    if (value == nullptr || value->value == nullptr || value->bytes == nullptr) {
        return n00b_result_err(n00b_uint128_t, N00B_STORE_NORM_ERR_ARG);
    }

    uint8_t scalar_tag = 0;
    if (!rocs_norm_scalar_tag(value->value, &scalar_tag)) {
        return n00b_result_err(n00b_uint128_t, N00B_STORE_NORM_ERR_TYPE);
    }

    n00b_string_t *path = rocs_norm_root_path(value->path);
    if (path == nullptr) {
        return n00b_result_err(n00b_uint128_t, N00B_STORE_NORM_ERR_ARG);
    }
    if (path->u8_bytes != 0 && path->data == nullptr) {
        return n00b_result_err(n00b_uint128_t, N00B_STORE_NORM_ERR_STATE);
    }

    n00b_size_t payload_len = n00b_buffer_len(value->bytes);
    if (payload_len != 0 && value->bytes->data == nullptr) {
        return n00b_result_err(n00b_uint128_t, N00B_STORE_NORM_ERR_STATE);
    }

    return rocs_norm_hash_bytes(kind,
                                scalar_tag,
                                path,
                                value->bytes->data,
                                (uint64_t)payload_len,
                                .allocator = allocator);
}

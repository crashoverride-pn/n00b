/*
 * json.c — JSON value types, recursive descent parser, and encoder.
 */

#include "n00b.h"
#include "parsers/json.h"
#include "core/alloc.h"
#include "core/thread.h"
#include "core/hash.h"
#include "core/static_objects.h"
#include "adt/list.h"
#include "core/atomic.h"
#include "util/parse_num.h"
#include "text/strings/fptostr.h"     // n00b_fptostr (libc-malloc-free double->str)
#include "text/strings/fmt_numbers.h" // n00b_fmt_int (native itoa, no libc)

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <errno.h>

// ============================================================================
// Constructors
// ============================================================================

/*
 * JSON nodes are variant-discriminated; there is intentionally no parallel
 * type field. Allocate each node with a scan shape matching the active
 * constructor so scalar payload words are not mistaken for pointers during
 * shard marshal, while pointer-backed variants still keep their children live.
 */
static const n00b_gc_struct_array_t json_node_value_pointer_shape = {
    .stride = 1,
    .offset = 1,
    .count  = 1,
};

static const n00b_static_identity_t json_node_value_pointer_identity = {
    .version      = N00B_STATIC_IDENTITY_VERSION,
    .kind         = N00B_STATIC_IDENTITY_MANUAL,
    .namespace_id = "json",
    .object_key   = "n00b_json_node_t.value-pointer.v1",
};

N00B_STATIC_OBJECT_DESCRIPTOR_WITH_IDENTITY(
    json_node_value_pointer_desc,
    &json_node_value_pointer_shape,
    sizeof(json_node_value_pointer_shape),
    typehash(n00b_gc_struct_array_t),
    N00B_STATIC_OBJECT_F_READONLY,
    N00B_GC_SCAN_KIND_NONE,
    nullptr,
    nullptr,
    UINT64_C(0x4a534f4e00040001),
    &json_node_value_pointer_identity);

static n00b_json_node_t *
json_node_scalar_alloc(n00b_allocator_t *allocator)
{
    return n00b_alloc_with_opts(
        n00b_json_node_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });
}

static n00b_json_node_t *
json_node_pointer_alloc(n00b_allocator_t *allocator)
{
    return n00b_alloc_with_opts(
        n00b_json_node_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
            .scan_kind = N00B_GC_SCAN_KIND_CALLBACK,
            .scan_cb   = n00b_gc_scan_cb_struct_field,
            .scan_user = (void *)&json_node_value_pointer_shape,
        });
}

n00b_json_node_t *
n00b_json_null_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_json_node_t *v = json_node_scalar_alloc(allocator);
    v->value = n00b_variant_set(n00b_json_value_t,
                                n00b_json_null_t,
                                ((n00b_json_null_t){}));
    return v;
}

n00b_json_node_t *
n00b_json_bool_new(bool val) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_json_node_t *v = json_node_scalar_alloc(allocator);
    v->value = n00b_variant_set(n00b_json_value_t, bool, val);
    return v;
}

n00b_json_node_t *
n00b_json_int_new(int64_t val) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_json_node_t *v = json_node_scalar_alloc(allocator);
    v->value = n00b_variant_set(n00b_json_value_t, int64_t, val);
    return v;
}

n00b_json_node_t *
n00b_json_double_new(double val) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_json_node_t *v = json_node_scalar_alloc(allocator);
    v->value = n00b_variant_set(n00b_json_value_t, double, val);
    return v;
}

n00b_json_node_t *
n00b_json_string_new(const char *val) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_json_node_t *v = json_node_pointer_alloc(allocator);
    v->value = n00b_variant_set(n00b_json_value_t,
                                n00b_string_t *,
                                val != nullptr
                                    ? n00b_string_from_cstr(
                                          val,
                                          .allocator = allocator)
                                    : nullptr);

    return v;
}

n00b_json_node_t *
n00b_json_string_new_from_n00b(n00b_string_t *s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_json_node_t *v = json_node_pointer_alloc(allocator);

    if (s != nullptr) {
        v->value = n00b_variant_set(n00b_json_value_t,
                                    n00b_string_t *,
                                    n00b_string_from_raw(s->data,
                                                         (int64_t)s->u8_bytes,
                                                         .allocator = allocator));
    }
    else {
        v->value = n00b_variant_set(n00b_json_value_t,
                                    n00b_string_t *,
                                    nullptr);
    }

    return v;
}

n00b_json_node_t *
n00b_json_array_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_json_node_t *v = json_node_pointer_alloc(allocator);
    n00b_json_array_t arr =
        n00b_list_new_private(n00b_json_node_t *,
                              .allocator = allocator,
                              .scan_kind = N00B_GC_SCAN_KIND_ALL);
    v->value = n00b_variant_set(n00b_json_value_t, n00b_json_array_t, arr);
    return v;
}

n00b_json_node_t *
n00b_json_object_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_json_node_t *v = json_node_pointer_alloc(allocator);
    n00b_json_object_t *obj =
        n00b_alloc_with_opts(n00b_json_object_t,
                             &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(obj,
                   .locked        = false,
                   .allocator     = allocator,
                   .hash          = n00b_string_hash,
                   .skip_obj_hash = true,
                   .key_scan_kind   = N00B_GC_SCAN_KIND_ALL,
                   .value_scan_kind = N00B_GC_SCAN_KIND_ALL);
    v->value = n00b_variant_set(n00b_json_value_t, n00b_json_object_t *, obj);
    return v;
}

// ============================================================================
// Mutation
// ============================================================================

void
n00b_json_array_push(n00b_json_node_t *arr, n00b_json_node_t *val)
{
    if (!n00b_json_is_array(arr)) return;
    n00b_json_array_t *items = n00b_json_as_array(arr);
    if (items == nullptr) return;
    n00b_list_push(*items, val);
}

void
n00b_json_object_put(n00b_json_node_t *obj, const char *key,
                      n00b_json_node_t *val)
{
    if (!n00b_json_is_object(obj) || !key) return;

    n00b_json_object_t *dict = n00b_json_as_object(obj);
    if (dict == nullptr) return;

    n00b_json_object_put_n00b(
        obj,
        n00b_string_from_cstr(key, .allocator = dict->allocator),
        val);
}

void
n00b_json_object_put_n00b(n00b_json_node_t *obj,
                          n00b_string_t    *key,
                          n00b_json_node_t *val)
{
    if (!n00b_json_is_object(obj) || !key) return;

    n00b_json_object_t *dict = n00b_json_as_object(obj);
    if (dict == nullptr) return;

    n00b_dict_put(dict, key, val);
}

n00b_json_node_t *
n00b_json_object_get(n00b_json_node_t *obj, n00b_string_t *key)
{
    n00b_json_object_t *dict = n00b_json_as_object(obj);
    if (dict == nullptr || key == nullptr) {
        return nullptr;
    }

    bool found = false;
    n00b_json_node_t *value = n00b_dict_get(dict, key, &found);
    return found ? value : nullptr;
}

n00b_json_node_t *
n00b_json_object_get_cstr(n00b_json_node_t *obj, const char *key)
{
    if (key == nullptr) {
        return nullptr;
    }
    return n00b_json_object_get(obj, n00b_string_from_cstr(key));
}

n00b_string_t *
n00b_json_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_JSON_OK:        return r"OK";
    case N00B_JSON_ERR_ARG:   return r"ARG";
    case N00B_JSON_ERR_TYPE:  return r"TYPE";
    case N00B_JSON_ERR_STATE: return r"STATE";
    }
    return r"UNKNOWN";
}

n00b_result_t(n00b_json_object_entry_list_t *)
n00b_json_object_entries(n00b_json_node_t *obj) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (obj == nullptr) {
        return n00b_result_err(n00b_json_object_entry_list_t *,
                               N00B_JSON_ERR_ARG);
    }

    if (n00b_json_type(obj) != N00B_JSON_OBJECT) {
        return n00b_result_err(n00b_json_object_entry_list_t *,
                               N00B_JSON_ERR_TYPE);
    }

    n00b_json_object_t *dict = n00b_json_as_object(obj);
    if (dict == nullptr) {
        return n00b_result_err(n00b_json_object_entry_list_t *,
                               N00B_JSON_ERR_STATE);
    }

    n00b_json_object_entry_list_t *entries = n00b_alloc_with_opts(
        n00b_json_object_entry_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    *entries = n00b_list_new_private(n00b_json_object_entry_t *,
                                     .allocator = allocator,
                                     .scan_kind = N00B_GC_SCAN_KIND_ALL);

    n00b_dict_foreach(dict, key, child, {
        if (key == nullptr || child == nullptr) {
            return n00b_result_err(n00b_json_object_entry_list_t *,
                                   N00B_JSON_ERR_STATE);
        }

        n00b_json_object_entry_t *entry = n00b_alloc_with_opts(
            n00b_json_object_entry_t,
            &(n00b_alloc_opts_t){
                .allocator = allocator,
            });
        entry->key   = key;
        entry->value = child;
        n00b_list_push(*entries, entry);
    });

    return n00b_result_ok(n00b_json_object_entry_list_t *, entries);
}

size_t
n00b_json_length(const n00b_json_node_t *val)
{
    if (!val) return 0;
    if (n00b_json_is_array(val)) {
        const n00b_json_array_t *arr = n00b_json_as_array_const(val);
        return arr == nullptr ? 0 : n00b_list_len(*arr);
    }
    if (n00b_json_is_object(val)) {
        const n00b_json_object_t *obj = n00b_json_as_object_const(val);
        return obj == nullptr ? 0 : (size_t)n00b_atomic_load(&obj->length);
    }
    return 0;
}

// ============================================================================
// Recursive descent parser
// ============================================================================

typedef struct {
    const char       *input;
    size_t            len;
    size_t            pos;
    size_t            depth;
    size_t            max_depth;
    const char       *error;
    n00b_allocator_t *allocator;
} json_parser_t;

static n00b_json_node_t *parse_value(json_parser_t *p);

static void
skip_whitespace(json_parser_t *p)
{
    while (p->pos < p->len) {
        char c = p->input[p->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
            p->pos++;
        else
            break;
    }
}

static bool
match_char(json_parser_t *p, char expected)
{
    skip_whitespace(p);
    if (p->pos < p->len && p->input[p->pos] == expected) {
        p->pos++;
        return true;
    }
    return false;
}

static bool
match_literal(json_parser_t *p, const char *lit)
{
    size_t n = strlen(lit);
    if (p->pos + n > p->len) return false;
    if (memcmp(p->input + p->pos, lit, n) != 0) return false;
    p->pos += n;
    return true;
}

static int
hex_digit_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

static inline bool
is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static char *
parse_string_content(json_parser_t *p)
{
    size_t max_len = p->len - p->pos;
    // max 4 bytes per UTF-8 char from \uXXXX, allocate generously
    char *out = n00b_alloc_array_with_opts(
        char,
        max_len * 4 + 1,
        &(n00b_alloc_opts_t){.allocator = p->allocator});
    size_t out_len = 0;

    while (p->pos < p->len) {
        char c = p->input[p->pos];

        if (c == '"') {
            p->pos++;
            out[out_len] = '\0';
            return out;
        }

        if (c == '\\') {
            p->pos++;
            if (p->pos >= p->len) {
                p->error = "unterminated string escape";
                n00b_free(out);
                return nullptr;
            }
            char esc = p->input[p->pos++];
            switch (esc) {
            case '"':  out[out_len++] = '"';  break;
            case '\\': out[out_len++] = '\\'; break;
            case '/':  out[out_len++] = '/';  break;
            case 'b':  out[out_len++] = '\b'; break;
            case 'f':  out[out_len++] = '\f'; break;
            case 'n':  out[out_len++] = '\n'; break;
            case 'r':  out[out_len++] = '\r'; break;
            case 't':  out[out_len++] = '\t'; break;
            case 'u': {
                if (p->pos + 4 > p->len) {
                    p->error = "incomplete unicode escape";
                    n00b_free(out);
                    return nullptr;
                }
                uint32_t cp = 0;
                for (int i = 0; i < 4; i++) {
                    int d = hex_digit_val(p->input[p->pos++]);
                    if (d < 0) {
                        p->error = "invalid hex digit in unicode escape";
                        n00b_free(out);
                        return nullptr;
                    }
                    cp = (cp << 4) | d;
                }
                // Handle surrogate pairs.
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    if (p->pos + 6 > p->len ||
                        p->input[p->pos] != '\\' ||
                        p->input[p->pos + 1] != 'u') {
                        p->error = "missing low surrogate";
                        n00b_free(out);
                        return nullptr;
                    }
                    p->pos += 2;
                    uint32_t low = 0;
                    for (int i = 0; i < 4; i++) {
                        int d = hex_digit_val(p->input[p->pos++]);
                        if (d < 0) {
                            p->error = "invalid hex digit in surrogate";
                            n00b_free(out);
                            return nullptr;
                        }
                        low = (low << 4) | d;
                    }
                    if (low < 0xDC00 || low > 0xDFFF) {
                        p->error = "invalid low surrogate";
                        n00b_free(out);
                        return nullptr;
                    }
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                }
                // Encode as UTF-8.
                if (cp < 0x80) {
                    out[out_len++] = (char)cp;
                }
                else if (cp < 0x800) {
                    out[out_len++] = (char)(0xC0 | (cp >> 6));
                    out[out_len++] = (char)(0x80 | (cp & 0x3F));
                }
                else if (cp < 0x10000) {
                    out[out_len++] = (char)(0xE0 | (cp >> 12));
                    out[out_len++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                    out[out_len++] = (char)(0x80 | (cp & 0x3F));
                }
                else {
                    out[out_len++] = (char)(0xF0 | (cp >> 18));
                    out[out_len++] = (char)(0x80 | ((cp >> 12) & 0x3F));
                    out[out_len++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                    out[out_len++] = (char)(0x80 | (cp & 0x3F));
                }
                break;
            }
            default:
                p->error = "invalid escape character";
                n00b_free(out);
                return nullptr;
            }
        }
        else if ((unsigned char)c < 0x20) {
            p->error = "unescaped control character in string";
            n00b_free(out);
            return nullptr;
        }
        else {
            out[out_len++] = c;
            p->pos++;
        }
    }

    p->error = "unterminated string";
    n00b_free(out);
    return nullptr;
}

static n00b_json_node_t *
parse_string(json_parser_t *p)
{
    char *s = parse_string_content(p);
    if (!s) return nullptr;

    n00b_json_node_t *v = json_node_pointer_alloc(p->allocator);
    v->value = n00b_variant_set(n00b_json_value_t,
                                n00b_string_t *,
                                n00b_string_from_cstr(
                                    s,
                                    .allocator = p->allocator));
    n00b_free(s);
    return v;
}

static n00b_json_node_t *
parse_number(json_parser_t *p)
{
    size_t start = p->pos;

    if (p->pos < p->len && p->input[p->pos] == '-')
        p->pos++;

    if (p->pos >= p->len || !is_digit(p->input[p->pos])) {
        p->error = "invalid number";
        return nullptr;
    }

    if (p->input[p->pos] == '0') {
        p->pos++;
        if (p->pos < p->len && is_digit(p->input[p->pos])) {
            p->error = "leading zeros not allowed";
            return nullptr;
        }
    }
    else {
        while (p->pos < p->len && is_digit(p->input[p->pos]))
            p->pos++;
    }

    bool is_float = false;

    if (p->pos < p->len && p->input[p->pos] == '.') {
        is_float = true;
        p->pos++;
        if (p->pos >= p->len || !is_digit(p->input[p->pos])) {
            p->error = "invalid number: no digits after decimal point";
            return nullptr;
        }
        while (p->pos < p->len && is_digit(p->input[p->pos]))
            p->pos++;
    }

    if (p->pos < p->len &&
        (p->input[p->pos] == 'e' || p->input[p->pos] == 'E')) {
        is_float = true;
        p->pos++;
        if (p->pos < p->len &&
            (p->input[p->pos] == '+' || p->input[p->pos] == '-'))
            p->pos++;
        if (p->pos >= p->len || !is_digit(p->input[p->pos])) {
            p->error = "invalid number: no digits in exponent";
            return nullptr;
        }
        while (p->pos < p->len && is_digit(p->input[p->pos]))
            p->pos++;
    }

    size_t num_len = p->pos - start;
    char num_buf[64];
    if (num_len >= sizeof(num_buf)) {
        p->error = "number too long";
        return nullptr;
    }
    memcpy(num_buf, p->input + start, num_len);
    num_buf[num_len] = '\0';

    n00b_json_node_t *v = json_node_scalar_alloc(p->allocator);

    /* Libc-free: strtoll/strtod are locale-aware and segfault on n00b
     * off-libc worker threads (NULL TLS locale). JSON is parsed on those
     * threads (e.g. JWT claim verification on the QUIC dispatch worker). */
    if (is_float) {
        n00b_result_t(double) r = n00b_parse_f64(num_buf, num_len);
        if (n00b_result_is_err(r)) {
            p->error = "number out of range";
            return nullptr;
        }
        v->value = n00b_variant_set(n00b_json_value_t,
                                    double,
                                    n00b_result_get(r));
    }
    else {
        n00b_result_t(int64_t) r = n00b_parse_i64(num_buf, num_len);
        if (n00b_result_is_ok(r)) {
            v->value = n00b_variant_set(n00b_json_value_t,
                                        int64_t,
                                        n00b_result_get(r));
        }
        else {
            /* ERANGE: value doesn't fit in int64 — represent as double.
             * (EINVAL can't occur: the scanner above already verified at
             * least one digit.) */
            n00b_result_t(double) rf = n00b_parse_f64(num_buf, num_len);
            if (n00b_result_is_err(rf)) {
                p->error = "number out of range";
                return nullptr;
            }
            v->value = n00b_variant_set(n00b_json_value_t,
                                        double,
                                        n00b_result_get(rf));
        }
    }

    return v;
}

static n00b_json_node_t *
parse_array(json_parser_t *p)
{
    if (p->depth >= p->max_depth) {
        p->error = "maximum nesting depth exceeded";
        return nullptr;
    }
    p->depth++;

    n00b_json_node_t *arr = n00b_json_array_new(.allocator = p->allocator);

    skip_whitespace(p);
    if (p->pos < p->len && p->input[p->pos] == ']') {
        p->pos++;
        p->depth--;
        return arr;
    }

    for (;;) {
        n00b_json_node_t *elem = parse_value(p);
        if (!elem) { p->depth--; return nullptr; }
        n00b_json_array_push(arr, elem);

        skip_whitespace(p);
        if (match_char(p, ']')) {
            p->depth--;
            return arr;
        }
        if (!match_char(p, ',')) {
            p->error = "expected ',' or ']' in array";
            p->depth--;
            return nullptr;
        }
    }
}

static n00b_json_node_t *
parse_object(json_parser_t *p)
{
    if (p->depth >= p->max_depth) {
        p->error = "maximum nesting depth exceeded";
        return nullptr;
    }
    p->depth++;

    n00b_json_node_t *obj = n00b_json_object_new(.allocator = p->allocator);

    skip_whitespace(p);
    if (p->pos < p->len && p->input[p->pos] == '}') {
        p->pos++;
        p->depth--;
        return obj;
    }

    for (;;) {
        skip_whitespace(p);
        if (!match_char(p, '"')) {
            p->error = "expected string key in object";
            p->depth--;
            return nullptr;
        }
        char *key = parse_string_content(p);
        if (!key) { p->depth--; return nullptr; }

        if (!match_char(p, ':')) {
            p->error = "expected ':' after key in object";
            n00b_free(key);
            p->depth--;
            return nullptr;
        }

        n00b_json_node_t *val = parse_value(p);
        if (!val) { n00b_free(key); p->depth--; return nullptr; }

        n00b_string_t *key_s =
            n00b_string_from_cstr(key, .allocator = p->allocator);
        n00b_free(key);
        n00b_json_object_put_n00b(obj, key_s, val);

        skip_whitespace(p);
        if (match_char(p, '}')) {
            p->depth--;
            return obj;
        }
        if (!match_char(p, ',')) {
            p->error = "expected ',' or '}' in object";
            p->depth--;
            return nullptr;
        }
    }
}

static n00b_json_node_t *
parse_value(json_parser_t *p)
{
    skip_whitespace(p);

    if (p->pos >= p->len) {
        p->error = "unexpected end of input";
        return nullptr;
    }

    char c = p->input[p->pos];

    switch (c) {
    case '"':
        p->pos++;
        return parse_string(p);
    case '{':
        p->pos++;
        return parse_object(p);
    case '[':
        p->pos++;
        return parse_array(p);
    case 't':
        if (!match_literal(p, "true")) {
            p->error = "invalid literal (expected 'true')";
            return nullptr;
        }
        return n00b_json_bool_new(true, .allocator = p->allocator);
    case 'f':
        if (!match_literal(p, "false")) {
            p->error = "invalid literal (expected 'false')";
            return nullptr;
        }
        return n00b_json_bool_new(false, .allocator = p->allocator);
    case 'n':
        if (!match_literal(p, "null")) {
            p->error = "invalid literal (expected 'null')";
            return nullptr;
        }
        return n00b_json_null_new(.allocator = p->allocator);
    case '-':
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
        return parse_number(p);
    default:
        p->error = "unexpected character";
        return nullptr;
    }
}

// ============================================================================
// Public parse API
// ============================================================================

n00b_json_node_t *
n00b_json_parse(const char *input, size_t input_len, const char **err_out) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!input || input_len == 0) {
        if (err_out) *err_out = "empty input";
        return nullptr;
    }

    json_parser_t p = {
        .input     = input,
        .len       = input_len,
        .pos       = 0,
        .depth     = 0,
        .max_depth = 256,
        .error     = nullptr,
        .allocator = allocator,
    };

    n00b_json_node_t *val = parse_value(&p);
    if (!val) {
        if (err_out) *err_out = p.error ? p.error : "parse error";
        return nullptr;
    }

    skip_whitespace(&p);
    if (p.pos < p.len) {
        if (err_out) *err_out = "trailing content after JSON value";
        return nullptr;
    }

    if (err_out) *err_out = nullptr;
    return val;
}

// ============================================================================
// JSON encoder
// ============================================================================

typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
    bool   pretty;
    int    indent;
    int    depth;
    bool   error;
    bool   canonical;
} json_encoder_t;

typedef struct {
    n00b_string_t          *key;
    const n00b_json_node_t *value;
} json_kv_pair_t;

static int
json_kv_cmp(const void *a, const void *b)
{
    const json_kv_pair_t *pa = (const json_kv_pair_t *)a;
    const json_kv_pair_t *pb = (const json_kv_pair_t *)b;
    size_t la = pa->key == nullptr ? 0 : pa->key->u8_bytes;
    size_t lb = pb->key == nullptr ? 0 : pb->key->u8_bytes;
    size_t lm = la < lb ? la : lb;
    int    r  = lm == 0 ? 0 : memcmp(pa->key->data, pb->key->data, lm);
    if (r != 0) return r;
    if (la < lb) return -1;
    if (la > lb) return 1;
    return 0;
}

static void
enc_ensure(json_encoder_t *e, size_t needed)
{
    if (e->error) return;
    size_t required = e->len + needed;
    if (required <= e->cap) return;

    size_t new_cap = e->cap ? e->cap * 2 : 256;
    while (new_cap < required) new_cap *= 2;

    // Grow buffers are pure scratch: superseded on each doubling (freed just
    // below) and, for the final one, copied into a durable result by
    // n00b_json_encode.  Take them from this thread's scratch pool (non-GC) so
    // n00b_free reclaims each immediately instead of churning the GC arena.
    char *new_buf = n00b_alloc_array(char,
                                     new_cap,
                                     .allocator = n00b_thread_scratch_pool());
    if (e->buf && e->len > 0) {
        memcpy(new_buf, e->buf, e->len);
    }
    if (e->buf) {
        n00b_free(e->buf);
    }
    e->buf = new_buf;
    e->cap = new_cap;
}

static void
enc_write(json_encoder_t *e, const char *s, size_t n)
{
    enc_ensure(e, n);
    if (e->error) return;
    memcpy(e->buf + e->len, s, n);
    e->len += n;
}

static void
enc_char(json_encoder_t *e, char c)
{
    enc_ensure(e, 1);
    if (e->error) return;
    e->buf[e->len++] = c;
}

static void
enc_str(json_encoder_t *e, const char *s)
{
    enc_write(e, s, strlen(s));
}

static void
enc_newline_indent(json_encoder_t *e)
{
    if (!e->pretty) return;
    enc_char(e, '\n');
    int spaces = e->depth * e->indent;
    for (int i = 0; i < spaces; i++) enc_char(e, ' ');
}

static void encode_value(json_encoder_t *e, const n00b_json_node_t *val);

static const char esc_quote[2]     = { '\\', '"' };
static const char esc_backslash[2] = { '\\', '\\' };
static const char esc_b[2]         = { '\\', 'b' };
static const char esc_f[2]         = { '\\', 'f' };
static const char esc_n[2]         = { '\\', 'n' };
static const char esc_r[2]         = { '\\', 'r' };
static const char esc_t[2]         = { '\\', 't' };

static void
encode_n00b_string(json_encoder_t *e, n00b_string_t *s)
{
    enc_char(e, '"');
    if (!s) { enc_char(e, '"'); return; }

    for (size_t i = 0; i < s->u8_bytes; i++) {
        unsigned char c = (unsigned char)s->data[i];
        switch (c) {
        case '"':  enc_write(e, esc_quote, 2);     break;
        case '\\': enc_write(e, esc_backslash, 2); break;
        case '\b': enc_write(e, esc_b, 2);         break;
        case '\f': enc_write(e, esc_f, 2);         break;
        case '\n': enc_write(e, esc_n, 2);         break;
        case '\r': enc_write(e, esc_r, 2);         break;
        case '\t': enc_write(e, esc_t, 2);         break;
        default:
            if (c < 0x20) {
                static const char hd[] = "0123456789abcdef";
                char hex[6];
                hex[0] = '\\';
                hex[1] = 'u';
                hex[2] = '0';
                hex[3] = '0';
                hex[4] = hd[(c >> 4) & 0xf];
                hex[5] = hd[c & 0xf];
                enc_write(e, hex, 6);
            }
            else {
                enc_char(e, (char)c);
            }
            break;
        }
    }
    enc_char(e, '"');
}

static void
encode_value(json_encoder_t *e, const n00b_json_node_t *val)
{
    if (e->error) return;

    if (!val) {
        enc_str(e, "null");
        return;
    }

    switch (n00b_json_type(val)) {
    case N00B_JSON_NULL:
        enc_str(e, "null");
        break;

    case N00B_JSON_BOOL:
        enc_str(e, n00b_json_as_bool(val) ? "true" : "false");
        break;

    case N00B_JSON_INT:
        // n00b_fmt_int (native itoa), NOT libc snprintf — keep the encoder off
        // libc entirely (see the DOUBLE case: a libc descent via snprintf ->
        // dtoa -> malloc -> pthread_self traps on n00b off-libc worker threads).
        enc_str(e, n00b_fmt_int(n00b_json_as_i64(val))->data);
        break;

    case N00B_JSON_DOUBLE: {
        char num[64];
        double n = n00b_json_as_f64(val);
        if (isinf(n) || isnan(n)) {
            enc_str(e, "null");
        }
        else {
            // n00b_fptostr, NOT libc snprintf("%.17g"): float snprintf formats
            // via dtoa, which mallocs a Bigint internally. On an n00b off-libc
            // worker thread (custom stack, not a fully-registered pthread) that
            // first libc malloc traps in _xzm_thread_cache_create_and_malloc ->
            // pthread_self (EXC_BREAKPOINT). This was the crayon-gw crasher in
            // the rocs store shard-append path; same fix as metrics_encode.c.
            int num_len     = n00b_fptostr(n, num);
            num[(num_len > 0 && num_len < (int)sizeof(num)) ? num_len : 0] = '\0';
            if (strchr(num, '.') == nullptr
                && strchr(num, 'e') == nullptr
                && strchr(num, 'E') == nullptr) {
                size_t len = strlen(num);
                if (len + 2 < sizeof(num)) {
                    num[len++] = '.';
                    num[len++] = '0';
                    num[len]   = '\0';
                }
            }
            enc_str(e, num);
        }
        break;
    }

    case N00B_JSON_STRING:
        encode_n00b_string(e, n00b_json_as_string(val));
        break;

    case N00B_JSON_ARRAY: {
        enc_char(e, '[');
        const n00b_json_array_t *arr = n00b_json_as_array_const(val);
        size_t n = arr == nullptr ? 0 : n00b_list_len(*arr);
        if (n > 0) {
            e->depth++;
            for (size_t i = 0; i < n; i++) {
                if (i > 0) enc_char(e, ',');
                enc_newline_indent(e);
                n00b_json_node_t *elem = n00b_list_get(*arr, i);
                encode_value(e, elem);
            }
            e->depth--;
            enc_newline_indent(e);
        }
        enc_char(e, ']');
        break;
    }

    case N00B_JSON_OBJECT: {
        enc_char(e, '{');
        n00b_json_object_t *obj =
            (n00b_json_object_t *)n00b_json_as_object_const(val);
        size_t n = obj == nullptr ? 0 : (size_t)n00b_atomic_load(&obj->length);
        if (n > 0) {
            e->depth++;

            if (e->canonical) {
                // Canonical mode: collect (key, value) pairs into a
                // temp array, sort lexicographically by key, then
                // emit in sorted order. Produces byte-stable output
                // for downstream consumers that hash / compare the
                // wire form (e.g. libchalk's ATTESTATION subtree).
                json_kv_pair_t *pairs = n00b_alloc_array(json_kv_pair_t, n);
                size_t live = 0;
                n00b_dict_foreach(obj, key, child, {
                    if (live >= n) break;
                    pairs[live].key   = key;
                    pairs[live].value = child;
                    live++;
                });
                qsort(pairs, live, sizeof(json_kv_pair_t), json_kv_cmp);
                for (size_t i = 0; i < live; i++) {
                    if (i > 0) enc_char(e, ',');
                    enc_newline_indent(e);
                    encode_n00b_string(e, pairs[i].key);
                    enc_char(e, ':');
                    if (e->pretty) enc_char(e, ' ');
                    encode_value(e, pairs[i].value);
                }
            } else {
                size_t count = 0;
                n00b_dict_foreach(obj, key, child, {
                    if (count > 0) enc_char(e, ',');
                    enc_newline_indent(e);
                    encode_n00b_string(e, key);
                    enc_char(e, ':');
                    if (e->pretty) enc_char(e, ' ');
                    encode_value(e, child);
                    count++;
                });
            }
            e->depth--;
            enc_newline_indent(e);
        }
        enc_char(e, '}');
        break;
    }
    }
}

// ============================================================================
// Public encode API
// ============================================================================

char *
n00b_json_encode(const n00b_json_node_t *val) _kargs
{
    bool pretty    = false;
    int  indent    = 2;
    bool canonical = false;
}
{
    json_encoder_t e = {
        .buf       = nullptr,
        .len       = 0,
        .cap       = 0,
        .pretty    = pretty,
        .indent    = indent > 0 ? indent : 2,
        .depth     = 0,
        .error     = false,
        .canonical = canonical,
    };

    encode_value(&e, val);
    if (!e.error) {
        enc_char(&e, '\0');
    }
    if (e.error) {
        if (e.buf != nullptr) {
            n00b_free(e.buf);
        }
        return nullptr;
    }

    // e.buf is in the per-thread scratch pool (off the GC heap).  Copy the
    // finished bytes into a durable result for the caller, then release the
    // scratch buffer.
    char *result = n00b_alloc_array(char, e.len);
    memcpy(result, e.buf, e.len);
    n00b_free(e.buf);
    return result;
}

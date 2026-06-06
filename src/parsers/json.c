/*
 * json.c — JSON value types, recursive descent parser, and encoder.
 */

#include "n00b.h"
#include "parsers/json.h"
#include "core/alloc.h"
#include "adt/list.h"
#include "core/atomic.h"
#include "core/hash.h"
#include "util/parse_num.h"
#define N00B_USE_INTERNAL_API
#include "adt/dict_untyped.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <errno.h>

// ============================================================================
// Constructors
// ============================================================================

n00b_json_node_t *
n00b_json_null_new(void)
{
    n00b_json_node_t *v = n00b_alloc(n00b_json_node_t);
    v->type = N00B_JSON_NULL;
    return v;
}

n00b_json_node_t *
n00b_json_bool_new(bool val)
{
    n00b_json_node_t *v = n00b_alloc(n00b_json_node_t);
    v->type    = N00B_JSON_BOOL;
    v->boolean = val;
    return v;
}

n00b_json_node_t *
n00b_json_int_new(int64_t val)
{
    n00b_json_node_t *v = n00b_alloc(n00b_json_node_t);
    v->type    = N00B_JSON_INT;
    v->integer = val;
    return v;
}

n00b_json_node_t *
n00b_json_double_new(double val)
{
    n00b_json_node_t *v = n00b_alloc(n00b_json_node_t);
    v->type   = N00B_JSON_DOUBLE;
    v->number = val;
    return v;
}

n00b_json_node_t *
n00b_json_string_new(const char *val)
{
    n00b_json_node_t *v = n00b_alloc(n00b_json_node_t);
    v->type = N00B_JSON_STRING;

    if (val) {
        size_t len = strlen(val);
        char *copy = n00b_alloc_array(char, len + 1);
        memcpy(copy, val, len);
        copy[len] = '\0';
        v->string = copy;
    }

    return v;
}

n00b_json_node_t *
n00b_json_string_new_from_n00b(n00b_string_t *s)
{
    n00b_json_node_t *v = n00b_alloc(n00b_json_node_t);
    v->type = N00B_JSON_STRING;

    if (s != nullptr) {
        size_t len  = (size_t)s->u8_bytes;
        char  *copy = n00b_alloc_array(char, len + 1);
        if (len > 0) {
            memcpy(copy, s->data, len);
        }
        copy[len] = '\0';
        v->string = copy;
    }

    return v;
}

n00b_json_node_t *
n00b_json_array_new(void)
{
    n00b_json_node_t *v = n00b_alloc(n00b_json_node_t);
    v->type  = N00B_JSON_ARRAY;
    v->array = n00b_list_new(n00b_json_node_t *);
    return v;
}

n00b_json_node_t *
n00b_json_object_new(void)
{
    n00b_json_node_t *v = n00b_alloc(n00b_json_node_t);
    v->type   = N00B_JSON_OBJECT;
    v->object = n00b_alloc(n00b_dict_untyped_t);
    n00b_dict_untyped_init(v->object, .hash = n00b_hash_cstring);
    return v;
}

// ============================================================================
// Mutation
// ============================================================================

void
n00b_json_array_push(n00b_json_node_t *arr, n00b_json_node_t *val)
{
    if (!arr || arr->type != N00B_JSON_ARRAY) return;
    n00b_list_push(arr->array, val);
}

void
n00b_json_object_put(n00b_json_node_t *obj, const char *key,
                      n00b_json_node_t *val)
{
    if (!obj || obj->type != N00B_JSON_OBJECT || !key) return;

    size_t klen = strlen(key);
    char  *kcopy = n00b_alloc_array(char, klen + 1);
    memcpy(kcopy, key, klen);
    kcopy[klen] = '\0';

    n00b_dict_untyped_put(obj->object, kcopy, val);
}

size_t
n00b_json_length(const n00b_json_node_t *val)
{
    if (!val) return 0;
    if (val->type == N00B_JSON_ARRAY)
        return n00b_list_len(val->array);
    if (val->type == N00B_JSON_OBJECT)
        return (size_t)n00b_atomic_load(&val->object->length);
    return 0;
}

// ============================================================================
// Recursive descent parser
// ============================================================================

typedef struct {
    const char *input;
    size_t      len;
    size_t      pos;
    size_t      depth;
    size_t      max_depth;
    const char *error;
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
    char  *out     = n00b_alloc_array(char, max_len * 4 + 1);
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
                    return nullptr;
                }
                uint32_t cp = 0;
                for (int i = 0; i < 4; i++) {
                    int d = hex_digit_val(p->input[p->pos++]);
                    if (d < 0) {
                        p->error = "invalid hex digit in unicode escape";
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
                        return nullptr;
                    }
                    p->pos += 2;
                    uint32_t low = 0;
                    for (int i = 0; i < 4; i++) {
                        int d = hex_digit_val(p->input[p->pos++]);
                        if (d < 0) {
                            p->error = "invalid hex digit in surrogate";
                            return nullptr;
                        }
                        low = (low << 4) | d;
                    }
                    if (low < 0xDC00 || low > 0xDFFF) {
                        p->error = "invalid low surrogate";
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
                return nullptr;
            }
        }
        else if ((unsigned char)c < 0x20) {
            p->error = "unescaped control character in string";
            return nullptr;
        }
        else {
            out[out_len++] = c;
            p->pos++;
        }
    }

    p->error = "unterminated string";
    return nullptr;
}

static n00b_json_node_t *
parse_string(json_parser_t *p)
{
    char *s = parse_string_content(p);
    if (!s) return nullptr;

    n00b_json_node_t *v = n00b_alloc(n00b_json_node_t);
    v->type   = N00B_JSON_STRING;
    v->string = s;
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

    n00b_json_node_t *v = n00b_alloc(n00b_json_node_t);

    /* Libc-free: strtoll/strtod are locale-aware and segfault on n00b
     * off-libc worker threads (NULL TLS locale). JSON is parsed on those
     * threads (e.g. JWT claim verification on the QUIC dispatch worker). */
    if (is_float) {
        n00b_result_t(double) r = n00b_parse_f64(num_buf, num_len);
        if (n00b_result_is_err(r)) {
            p->error = "number out of range";
            return nullptr;
        }
        v->type   = N00B_JSON_DOUBLE;
        v->number = n00b_result_get(r);
    }
    else {
        n00b_result_t(int64_t) r = n00b_parse_i64(num_buf, num_len);
        if (n00b_result_is_ok(r)) {
            v->type    = N00B_JSON_INT;
            v->integer = n00b_result_get(r);
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
            v->type   = N00B_JSON_DOUBLE;
            v->number = n00b_result_get(rf);
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

    n00b_json_node_t *arr = n00b_json_array_new();

    skip_whitespace(p);
    if (p->pos < p->len && p->input[p->pos] == ']') {
        p->pos++;
        p->depth--;
        return arr;
    }

    for (;;) {
        n00b_json_node_t *elem = parse_value(p);
        if (!elem) { p->depth--; return nullptr; }
        n00b_list_push(arr->array, elem);

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

    n00b_json_node_t *obj = n00b_json_object_new();

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
            p->depth--;
            return nullptr;
        }

        n00b_json_node_t *val = parse_value(p);
        if (!val) { p->depth--; return nullptr; }

        n00b_dict_untyped_put(obj->object, key, val);

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
        return n00b_json_bool_new(true);
    case 'f':
        if (!match_literal(p, "false")) {
            p->error = "invalid literal (expected 'false')";
            return nullptr;
        }
        return n00b_json_bool_new(false);
    case 'n':
        if (!match_literal(p, "null")) {
            p->error = "invalid literal (expected 'null')";
            return nullptr;
        }
        return n00b_json_null_new();
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
n00b_json_parse(const char *input, size_t input_len, const char **err_out)
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
    const char             *key;
    const n00b_json_node_t *value;
} json_kv_pair_t;

static int
json_kv_cmp(const void *a, const void *b)
{
    const json_kv_pair_t *pa = (const json_kv_pair_t *)a;
    const json_kv_pair_t *pb = (const json_kv_pair_t *)b;
    return strcmp(pa->key, pb->key);
}

static void
enc_ensure(json_encoder_t *e, size_t needed)
{
    if (e->error) return;
    size_t required = e->len + needed;
    if (required <= e->cap) return;

    size_t new_cap = e->cap ? e->cap * 2 : 256;
    while (new_cap < required) new_cap *= 2;

    char *new_buf = n00b_alloc_array(char, new_cap);
    if (e->buf && e->len > 0) {
        memcpy(new_buf, e->buf, e->len);
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
encode_string(json_encoder_t *e, const char *s)
{
    enc_char(e, '"');
    if (!s) { enc_char(e, '"'); return; }

    const char *p;
    for (p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
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

    switch (val->type) {
    case N00B_JSON_NULL:
        enc_str(e, "null");
        break;

    case N00B_JSON_BOOL:
        enc_str(e, val->boolean ? "true" : "false");
        break;

    case N00B_JSON_INT: {
        char num[32];
        snprintf(num, sizeof(num), "%lld", (long long)val->integer);
        enc_str(e, num);
        break;
    }

    case N00B_JSON_DOUBLE: {
        char num[64];
        if (isinf(val->number) || isnan(val->number)) {
            enc_str(e, "null");
        }
        else {
            snprintf(num, sizeof(num), "%.17g", val->number);
            enc_str(e, num);
        }
        break;
    }

    case N00B_JSON_STRING:
        encode_string(e, val->string);
        break;

    case N00B_JSON_ARRAY: {
        enc_char(e, '[');
        size_t n = n00b_list_len(val->array);
        if (n > 0) {
            e->depth++;
            for (size_t i = 0; i < n; i++) {
                if (i > 0) enc_char(e, ',');
                enc_newline_indent(e);
                n00b_json_node_t *elem = n00b_list_get(val->array, i);
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
        size_t n = (size_t)n00b_atomic_load(&val->object->length);
        if (n > 0) {
            e->depth++;
            n00b_dict_untyped_store_t *store =
                n00b_atomic_load(&val->object->store);
            uint32_t last = store->last_slot;

            if (e->canonical) {
                // Canonical mode: collect (key, value) pairs into a
                // temp array, sort lexicographically by key, then
                // emit in sorted order. Produces byte-stable output
                // for downstream consumers that hash / compare the
                // wire form (e.g. libchalk's ATTESTATION subtree).
                json_kv_pair_t *pairs = n00b_alloc_array(json_kv_pair_t, n);
                size_t live = 0;
                for (uint32_t i = 0; i <= last; i++) {
                    n00b_dict_untyped_bucket_t *b = &store->buckets[i];
                    uint32_t flags = n00b_atomic_load(&b->flags);
                    if (b->hv == 0 || (flags & 4)) continue;
                    if (live >= n) break;
                    pairs[live].key   = (const char *)b->key;
                    pairs[live].value = (const n00b_json_node_t *)b->value;
                    live++;
                }
                qsort(pairs, live, sizeof(json_kv_pair_t), json_kv_cmp);
                for (size_t i = 0; i < live; i++) {
                    if (i > 0) enc_char(e, ',');
                    enc_newline_indent(e);
                    encode_string(e, pairs[i].key);
                    enc_char(e, ':');
                    if (e->pretty) enc_char(e, ' ');
                    encode_value(e, pairs[i].value);
                }
            } else {
                size_t count = 0;
                for (uint32_t i = 0; i <= last; i++) {
                    n00b_dict_untyped_bucket_t *b = &store->buckets[i];
                    uint32_t flags = n00b_atomic_load(&b->flags);
                    if (b->hv == 0 || (flags & 4)) continue;
                    if (count > 0) enc_char(e, ',');
                    enc_newline_indent(e);
                    encode_string(e, (const char *)b->key);
                    enc_char(e, ':');
                    if (e->pretty) enc_char(e, ' ');
                    encode_value(e, (const n00b_json_node_t *)b->value);
                    count++;
                }
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
    if (e.error) return nullptr;

    enc_char(&e, '\0');
    if (e.error) return nullptr;

    return e.buf;
}

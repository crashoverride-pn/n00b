// rewrite.c — slay-level rewrite mechanism.
//
// See include/slay/rewrite.h for the public surface. This file
// implements:
//   - The internal builder API used by the BNF loader to attach
//     capture tables + rewrite blocks to productions.
//   - A small block-body parser that splits a `rewrite { … }` body
//     into key:value fields (with `[==[ … ]==]` heredoc support).
//   - The apply engines: text-mode (verbatim source-byte extraction
//     by walking the captured subtree's token leaves) and subtree-mode
//     (re-render via n00b_pretty_print).
//   - The public predicates / accessors.
//
// Storage model (DF-L decision):
//   We hang two pointers off `n00b_parse_rule_t`: `rewrite` ->
//   `n00b_rewrite_info_t *` and `captures` -> `n00b_capture_table_t *`.
//   Both are nullptr by default; only productions that use the
//   feature pay any storage cost. The structures themselves carry
//   typed n00b containers.
//
// Block tokenization (DF-K decision):
//   The BNF tokenizer emits a single `BNF_TOK_REWRITE_BLOCK` token
//   whose value is the raw block body (everything between the
//   leveled `{=*` opener and the matching `=*}` closer, exclusive
//   of the delimiters themselves). Field-parsing happens in this
//   file from that raw body. Mismatched levels produce a tokenizer
//   error (the closer-search code in `bnf.c` requires the `=` count
//   to match the opener's).

#include "slay/rewrite.h"
#include "slay/pprint.h"
#include "slay/parse_tree.h"
#include "slay/token.h"
#include "internal/slay/grammar_internal.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/hash.h"
#include "core/string.h"
#include "text/strings/string_ops.h"
#include "adt/dict.h"
#include "adt/list.h"
#include "adt/option.h"
#include "adt/result.h"
#include "adt/tree.h"

#include <stdint.h>
#include <string.h>

// ============================================================================
// Sidecar structures
// ============================================================================

// One capture: `$name:<nt>` declared at position `child_ix` in the
// production's RHS.
typedef struct {
    n00b_string_t *name;
    int32_t        child_ix;
} n00b_capture_entry_t;

// Per-production capture table.
typedef struct {
    n00b_list_t(n00b_capture_entry_t *)    entries;
    // Quick name -> child_ix lookup.
    n00b_dict_t(n00b_string_t *, int64_t) *by_name;
} n00b_capture_table_t;

// Per-production rewrite block: parsed key:value field map.
//
// `template_field` is the required `template:` value. `fields` carries
// the entire parsed field set (so callers can iterate via
// `n00b_production_rewrite_field`).
typedef struct {
    n00b_string_t                                  *template_field;
    n00b_dict_t(n00b_string_t *, n00b_string_t *)  *fields;
} n00b_rewrite_info_t;

// Forward declarations (local helpers used out-of-order).
static void rewrite_emit_token_bytes(n00b_parse_tree_t *t, n00b_buffer_t *out,
                                      bool *emitted_first,
                                      n00b_allocator_t *allocator);

// ============================================================================
// Small helpers
// ============================================================================

static n00b_string_t *
slice_to_string(const char *base, size_t start, size_t end,
                n00b_allocator_t *allocator)
{
    if (end <= start) {
        return n00b_string_empty(.allocator = allocator);
    }
    return n00b_string_from_raw((char *)(base + start),
                                 (int64_t)(end - start),
                                 .allocator = allocator);
}

// Strip ASCII spaces, tabs, CR, and NL from both ends of [start, end).
// Adjusts the half-open span in place. Does NOT touch the bytes.
static void
strip_ascii_ws(const char *base, size_t *start, size_t *end)
{
    while (*start < *end) {
        char c = base[*start];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            (*start)++;
            continue;
        }
        break;
    }
    while (*end > *start) {
        char c = base[*end - 1];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            (*end)--;
            continue;
        }
        break;
    }
}

// Is `ch` legal in a field key? Field keys are identifier-shaped:
// `[A-Za-z_][A-Za-z0-9_]*`.
static bool
is_key_start(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static bool
is_key_continue(char c)
{
    return is_key_start(c) || (c >= '0' && c <= '9');
}

// At `data[pos]`, attempt to parse a `key:` at block scope (after
// optional ASCII horizontal whitespace, leading from `pos`).
//
// Returns true and sets the key span (key_start_out, key_end_out)
// + colon_end_out (one past the colon) if a `key:` was recognized.
// Otherwise returns false.
static bool
match_key_at(const char *data, size_t len, size_t pos,
             size_t *key_start_out, size_t *key_end_out,
             size_t *colon_end_out)
{
    while (pos < len && (data[pos] == ' ' || data[pos] == '\t')) {
        pos++;
    }
    if (pos >= len || !is_key_start(data[pos])) {
        return false;
    }
    size_t ks = pos;
    while (pos < len && is_key_continue(data[pos])) {
        pos++;
    }
    size_t ke = pos;
    if (pos >= len || data[pos] != ':') {
        return false;
    }
    *key_start_out = ks;
    *key_end_out   = ke;
    *colon_end_out = pos + 1;
    return true;
}

// Recognize a heredoc opener `[=*[` at `data[pos]`. On success returns
// true, *level_out = count of '=' between the brackets, and
// *body_start_out = one past the opener.
static bool
match_heredoc_open(const char *data, size_t len, size_t pos,
                   int *level_out, size_t *body_start_out)
{
    if (pos >= len || data[pos] != '[') {
        return false;
    }
    size_t p     = pos + 1;
    int    level = 0;
    while (p < len && data[p] == '=') {
        level++;
        p++;
    }
    if (p >= len || data[p] != '[') {
        return false;
    }
    *level_out      = level;
    *body_start_out = p + 1;
    return true;
}

// Given a heredoc body that opened with `level` `=` chars at
// `data[body_start]`, find the matching `]=*]` closer. Returns true
// and sets *body_end_out (exclusive) + *closer_end_out (one past `]`).
static bool
find_heredoc_close(const char *data, size_t len, size_t body_start,
                   int level, size_t *body_end_out, size_t *closer_end_out)
{
    size_t p = body_start;
    while (p < len) {
        if (data[p] == ']') {
            size_t scan = p + 1;
            int    eqs  = 0;
            while (scan < len && data[scan] == '=') {
                eqs++;
                scan++;
            }
            if (eqs == level && scan < len && data[scan] == ']') {
                *body_end_out   = p;
                *closer_end_out = scan + 1;
                return true;
            }
        }
        p++;
    }
    return false;
}

// ============================================================================
// Block-body field parser
// ============================================================================
//
// Input: the raw bytes of a rewrite block body (between `{=*` and
// `=*}` exclusive). Output: a fresh dict of (key -> value) plus the
// `template:` value pulled out for fast access.
//
// Recognition rules:
//   - A field starts at a `key:` token found at "block scope" (after
//     a newline + optional horizontal whitespace, or at offset 0).
//   - The value runs from one past the colon to the start of the next
//     `key:` at block scope, OR the end of the body — whichever
//     comes first.
//   - Inside a `[=*[ ... ]=*]` heredoc the parser does not look for
//     a `key:` separator; the heredoc takes everything between its
//     opener and matched closer literally.
//   - When a field value is a single `[=*[ ... ]=*]` heredoc with
//     only surrounding whitespace, the field value is the heredoc
//     body byte-exact (preserves whitespace + allows `key:` inside).
//   - Otherwise the raw value span gets leading/trailing ASCII
//     whitespace stripped.
//
// Returns true iff parsing succeeded AND at least the `template:`
// field was found. The `allocator` is threaded into every per-field
// string allocation; pass nullptr for runtime default.
static bool
parse_block_body(n00b_string_t       *body,
                 n00b_rewrite_info_t *out,
                 n00b_allocator_t    *allocator)
{
    const char *data = body ? body->data : nullptr;
    size_t      len  = body ? body->u8_bytes : 0;

    if (!data) {
        return false;
    }

    size_t pos = 0;

    // Skip leading whitespace before the first field.
    while (pos < len && (data[pos] == ' ' || data[pos] == '\t'
                         || data[pos] == '\n' || data[pos] == '\r')) {
        pos++;
    }

    while (pos < len) {
        size_t key_s   = 0;
        size_t key_e   = 0;
        size_t after_c = 0;
        if (!match_key_at(data, len, pos, &key_s, &key_e, &after_c)) {
            // Skip stray content to next newline.
            while (pos < len && data[pos] != '\n') {
                pos++;
            }
            if (pos < len) {
                pos++;
            }
            continue;
        }

        n00b_string_t *key = slice_to_string(data, key_s, key_e, allocator);

        size_t val_start_raw = after_c;
        size_t scan          = after_c;
        size_t value_end     = len;

        while (scan < len) {
            if (data[scan] == '[') {
                int    hd_level = 0;
                size_t hd_body  = 0;
                if (match_heredoc_open(data, len, scan,
                                        &hd_level, &hd_body)) {
                    size_t hd_end       = 0;
                    size_t hd_close_end = 0;
                    if (find_heredoc_close(data, len, hd_body, hd_level,
                                            &hd_end, &hd_close_end)) {
                        scan = hd_close_end;
                        continue;
                    }
                    scan = len;
                    break;
                }
            }
            if (data[scan] == '\n') {
                size_t pk_s = 0, pk_e = 0, pk_after = 0;
                if (match_key_at(data, len, scan + 1,
                                  &pk_s, &pk_e, &pk_after)) {
                    value_end = scan;
                    break;
                }
            }
            scan++;
        }
        if (scan == len) {
            value_end = len;
        }

        // Try heredoc-as-whole-value first (preserves bytes exactly).
        size_t v_s = val_start_raw;
        size_t v_e = value_end;
        strip_ascii_ws(data, &v_s, &v_e);

        n00b_string_t *value = nullptr;

        if (v_s < v_e && data[v_s] == '[') {
            int    hd_level = 0;
            size_t hd_body  = 0;
            if (match_heredoc_open(data, len, v_s,
                                    &hd_level, &hd_body)) {
                size_t hd_end       = 0;
                size_t hd_close_end = 0;
                if (find_heredoc_close(data, len, hd_body, hd_level,
                                        &hd_end, &hd_close_end)
                    && hd_close_end == v_e) {
                    value = slice_to_string(data, hd_body, hd_end, allocator);
                }
            }
        }
        if (!value) {
            value = slice_to_string(data, v_s, v_e, allocator);
        }

        n00b_dict_put(out->fields, key, value);

        if (n00b_unicode_str_eq(key, r"template")) {
            out->template_field = value;
        }

        pos = value_end;
        while (pos < len && (data[pos] == ' ' || data[pos] == '\t'
                             || data[pos] == '\n' || data[pos] == '\r')) {
            pos++;
        }
    }

    return out->template_field != nullptr;
}

// ============================================================================
// Internal builders (called from the BNF loader)
// ============================================================================

bool
_n00b_production_attach_rewrite(n00b_production_t *p, n00b_string_t *body) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!p) {
        return false;
    }

    n00b_rewrite_info_t *info = n00b_alloc_with_opts(
        n00b_rewrite_info_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    info->template_field      = nullptr;
    info->fields              = n00b_alloc_with_opts(
        n00b_dict_t(n00b_string_t *, n00b_string_t *),
        &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(info->fields,
                   .hash          = n00b_string_hash,
                   .skip_obj_hash = true,
                   .allocator     = allocator);

    if (!parse_block_body(body, info, allocator)) {
        n00b_free(info->fields);
        n00b_free(info);
        return false;
    }

    p->rewrite = info;
    return true;
}

void
_n00b_production_add_capture(n00b_production_t *p,
                             n00b_string_t     *name,
                             int32_t            child_ix) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!p || !name) {
        return;
    }

    n00b_capture_table_t *table = (n00b_capture_table_t *)p->captures;
    if (!table) {
        table          = n00b_alloc_with_opts(n00b_capture_table_t,
                                              &(n00b_alloc_opts_t){.allocator = allocator});
        table->entries = n00b_list_new_private(n00b_capture_entry_t *,
                                                .allocator = allocator);
        table->by_name = n00b_alloc_with_opts(n00b_dict_t(n00b_string_t *, int64_t),
                                              &(n00b_alloc_opts_t){.allocator = allocator});
        n00b_dict_init(table->by_name,
                       .hash          = n00b_string_hash,
                       .skip_obj_hash = true,
                       .allocator     = allocator);
        p->captures = table;
    }

    n00b_capture_entry_t *e = n00b_alloc_with_opts(
        n00b_capture_entry_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    e->name     = name;
    e->child_ix = child_ix;
    n00b_list_push(table->entries, e);

    int64_t ix64 = (int64_t)child_ix;
    n00b_dict_put(table->by_name, name, ix64);
}

// ============================================================================
// Predicates / accessors
// ============================================================================

bool
n00b_production_has_rewrite(n00b_production_t *p)
{
    if (!p) {
        return false;
    }
    n00b_rewrite_info_t *info = (n00b_rewrite_info_t *)p->rewrite;
    return info != nullptr && info->template_field != nullptr;
}

n00b_option_t(n00b_string_t *)
n00b_production_rewrite_field(n00b_production_t *p, n00b_string_t *field_name)
{
    if (!p || !field_name) {
        return n00b_option_none(n00b_string_t *);
    }
    n00b_rewrite_info_t *info = (n00b_rewrite_info_t *)p->rewrite;
    if (!info || !info->fields) {
        return n00b_option_none(n00b_string_t *);
    }
    bool           found = false;
    n00b_string_t *val   = n00b_dict_get(info->fields, field_name, &found);
    if (!found) {
        return n00b_option_none(n00b_string_t *);
    }
    return n00b_option_set(n00b_string_t *, val);
}

n00b_list_t(n00b_string_t *) *
n00b_production_capture_names(n00b_production_t *p) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_list_t(n00b_string_t *) *out =
        n00b_alloc_with_opts(n00b_list_t(n00b_string_t *),
                             &(n00b_alloc_opts_t){.allocator = allocator});
    *out = n00b_list_new_private(n00b_string_t *, .allocator = allocator);
    if (!p) {
        return out;
    }
    n00b_capture_table_t *table = (n00b_capture_table_t *)p->captures;
    if (!table) {
        return out;
    }
    for (size_t i = 0; i < n00b_list_len(table->entries); i++) {
        n00b_capture_entry_t *e = n00b_list_get(table->entries, i);
        n00b_list_push(*out, e->name);
    }
    return out;
}

// ============================================================================
// Apply engines
// ============================================================================

typedef struct {
    n00b_grammar_t *grammar;
    bool            subtree_mode;
} n00b_apply_ctx_t;

// Subtree-mode grammar back-channel — see end of file.
extern n00b_grammar_t *_n00b_rewrite_current_grammar(void);

static n00b_err_t
substitute_capture(n00b_capture_table_t *captures,
                   n00b_parse_tree_t    *node,
                   n00b_string_t        *capture_name,
                   n00b_buffer_t        *out,
                   n00b_apply_ctx_t     *ctx,
                   n00b_allocator_t     *allocator)
{
    if (!captures || !captures->by_name) {
        return N00B_ERR_REWRITE_UNDEFINED_CAPTURE;
    }

    bool    found      = false;
    int64_t child_ix64 = n00b_dict_get(captures->by_name, capture_name, &found);
    if (!found) {
        return N00B_ERR_REWRITE_UNDEFINED_CAPTURE;
    }
    int32_t child_ix = (int32_t)child_ix64;

    if (n00b_tree_is_leaf(node) || child_ix < 0
        || (size_t)child_ix >= n00b_tree_num_children(node)) {
        return N00B_ERR_REWRITE_NO_CHILD;
    }

    n00b_parse_tree_t *child = n00b_tree_child(node, (size_t)child_ix);

    if (ctx->subtree_mode) {
        auto rr = n00b_pretty_print(ctx->grammar, child,
                                     .allocator = allocator);
        if (n00b_result_is_err(rr)) {
            return N00B_ERR_REWRITE_PPRINT_FAILED;
        }
        n00b_string_t *rendered = n00b_result_get(rr);
        if (rendered && rendered->u8_bytes > 0) {
            n00b_buffer_t *piece = n00b_buffer_from_bytes(
                rendered->data, (int64_t)rendered->u8_bytes,
                .allocator = allocator);
            n00b_buffer_concat(out, piece);
        }
        return 0;
    }

    // Text mode: walk all token leaves under `child` in source order
    // and emit their `value` strings, with leading_trivia inserted
    // between adjacent tokens. The very first token's leading trivia
    // is suppressed (we don't want to prepend the capture's leading
    // whitespace into the substitution slot).
    bool emitted_first = false;
    rewrite_emit_token_bytes(child, out, &emitted_first, allocator);
    return 0;
}

static void
rewrite_emit_token_bytes(n00b_parse_tree_t *t, n00b_buffer_t *out,
                          bool *emitted_first, n00b_allocator_t *allocator)
{
    if (!t) {
        return;
    }
    if (n00b_pt_is_token(t)) {
        n00b_token_info_t *tok = n00b_parse_node_token(t);
        if (!tok) {
            return;
        }
        if (*emitted_first && tok->leading_trivia) {
            n00b_trivia_t *tv;
            for (tv = tok->leading_trivia; tv; tv = tv->next) {
                if (tv->text && tv->text->u8_bytes > 0) {
                    n00b_buffer_t *piece = n00b_buffer_from_bytes(
                        tv->text->data, (int64_t)tv->text->u8_bytes,
                        .allocator = allocator);
                    n00b_buffer_concat(out, piece);
                }
            }
        }
        else if (*emitted_first) {
            char           sp    = ' ';
            n00b_buffer_t *piece = n00b_buffer_from_bytes(&sp, 1,
                                                          .allocator = allocator);
            n00b_buffer_concat(out, piece);
        }

        if (n00b_option_is_set(tok->value)) {
            n00b_string_t *v = n00b_option_get(tok->value);
            if (v && v->u8_bytes > 0) {
                n00b_buffer_t *piece = n00b_buffer_from_bytes(
                    v->data, (int64_t)v->u8_bytes,
                    .allocator = allocator);
                n00b_buffer_concat(out, piece);
            }
        }
        *emitted_first = true;
        return;
    }

    size_t n = n00b_tree_num_children(t);
    for (size_t i = 0; i < n; i++) {
        rewrite_emit_token_bytes(n00b_tree_child(t, i), out,
                                  emitted_first, allocator);
    }
}

// Walk a template string scanning for `$name` / `${name}` refs.
// For each, call `substitute_capture`. Concatenate everything onto
// `out`.
static n00b_err_t
apply_template(n00b_string_t        *tmpl,
               n00b_capture_table_t *captures,
               n00b_parse_tree_t    *node,
               n00b_buffer_t        *out,
               n00b_apply_ctx_t     *ctx,
               n00b_allocator_t     *allocator)
{
    if (!tmpl) {
        return N00B_ERR_REWRITE_NO_TEMPLATE;
    }
    const char *data      = tmpl->data;
    size_t      len       = tmpl->u8_bytes;
    size_t      pos       = 0;
    size_t      run_start = 0;

    while (pos < len) {
        if (data[pos] == '$') {
            if (pos > run_start) {
                n00b_buffer_t *piece = n00b_buffer_from_bytes(
                    (char *)(data + run_start),
                    (int64_t)(pos - run_start),
                    .allocator = allocator);
                n00b_buffer_concat(out, piece);
            }

            if (pos + 1 < len && data[pos + 1] == '$') {
                char           dollar = '$';
                n00b_buffer_t *piece  = n00b_buffer_from_bytes(&dollar, 1,
                                                               .allocator = allocator);
                n00b_buffer_concat(out, piece);
                pos += 2;
                run_start = pos;
                continue;
            }

            size_t name_start = 0;
            size_t name_end   = 0;
            size_t after      = pos;

            if (pos + 1 < len && data[pos + 1] == '{') {
                name_start = pos + 2;
                size_t p   = name_start;
                while (p < len && data[p] != '}') {
                    p++;
                }
                if (p >= len) {
                    // Unterminated ${ — emit literal `${` and skip.
                    n00b_buffer_t *piece = n00b_buffer_from_bytes(
                        (char *)(data + pos), 2,
                        .allocator = allocator);
                    n00b_buffer_concat(out, piece);
                    pos += 2;
                    run_start = pos;
                    continue;
                }
                name_end = p;
                after    = p + 1;
            }
            else {
                name_start = pos + 1;
                size_t p   = name_start;
                while (p < len && is_key_continue(data[p])) {
                    p++;
                }
                if (p == name_start) {
                    char           dollar = '$';
                    n00b_buffer_t *piece  = n00b_buffer_from_bytes(&dollar, 1,
                                                                   .allocator = allocator);
                    n00b_buffer_concat(out, piece);
                    pos += 1;
                    run_start = pos;
                    continue;
                }
                name_end = p;
                after    = p;
            }

            n00b_string_t *capname = slice_to_string(data, name_start,
                                                     name_end, allocator);
            n00b_err_t e = substitute_capture(captures, node, capname,
                                               out, ctx, allocator);
            if (e != 0) {
                return e;
            }

            pos       = after;
            run_start = pos;
            continue;
        }
        pos++;
    }

    if (pos > run_start) {
        n00b_buffer_t *piece = n00b_buffer_from_bytes(
            (char *)(data + run_start), (int64_t)(pos - run_start),
            .allocator = allocator);
        n00b_buffer_concat(out, piece);
    }

    return 0;
}

static n00b_result_t(n00b_string_t *)
do_rewrite(n00b_production_t *p, n00b_parse_tree_t *node,
           bool subtree_mode, n00b_allocator_t *allocator)
{
    if (!p || !node) {
        return n00b_result_err(n00b_string_t *, N00B_ERR_REWRITE_NULL_INPUT);
    }

    n00b_rewrite_info_t *info = (n00b_rewrite_info_t *)p->rewrite;
    if (!info) {
        return n00b_result_err(n00b_string_t *, N00B_ERR_REWRITE_NO_BLOCK);
    }
    if (!info->template_field) {
        return n00b_result_err(n00b_string_t *, N00B_ERR_REWRITE_NO_TEMPLATE);
    }

    n00b_apply_ctx_t ctx = {
        .grammar      = _n00b_rewrite_current_grammar(),
        .subtree_mode = subtree_mode,
    };

    n00b_buffer_t *out = n00b_buffer_empty(.allocator = allocator);

    n00b_capture_table_t *captures = (n00b_capture_table_t *)p->captures;
    n00b_err_t            err      = apply_template(info->template_field,
                                                     captures, node, out, &ctx,
                                                     allocator);
    if (err != 0) {
        return n00b_result_err(n00b_string_t *, err);
    }

    n00b_string_t *result = n00b_string_from_raw(out->data,
                                                  (int64_t)out->byte_len,
                                                  .allocator = allocator);
    return n00b_result_ok(n00b_string_t *, result);
}

n00b_result_t(n00b_string_t *)
n00b_production_rewrite_text(n00b_production_t *p,
                              n00b_parse_tree_t *node) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return do_rewrite(p, node, false, allocator);
}

n00b_result_t(n00b_string_t *)
n00b_production_rewrite_subtree(n00b_production_t *p,
                                 n00b_parse_tree_t *node) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return do_rewrite(p, node, true, allocator);
}

// ============================================================================
// Subtree-mode grammar back-channel
// ============================================================================
//
// Subtree-mode needs a grammar to drive the pretty-printer, but the
// public rewrite API takes only (production, parse-tree-node) plus
// kwargs. Threading the grammar through is doable, but the design pins
// the API surface to match the syntax spec exactly. We use a small
// explicit "current grammar" back-channel that the caller configures
// with n00b_rewrite_set_grammar before calling subtree-mode. Text-mode
// does not need this.
//
// Thread-safety: `current_rewrite_grammar` is module-level mutable
// state. Concurrent callers from different threads MUST serialize
// externally; this module does not acquire a lock around the grammar
// pointer. Single-threaded callers can ignore this caveat. Text-mode
// rewrites never touch this state and are unaffected.

static n00b_grammar_t *current_rewrite_grammar = nullptr;

void
n00b_rewrite_set_grammar(n00b_grammar_t *g)
{
    current_rewrite_grammar = g;
}

n00b_grammar_t *
_n00b_rewrite_current_grammar(void)
{
    return current_rewrite_grammar;
}

// ============================================================================
// Error-string accessor
// ============================================================================

n00b_string_t *
n00b_rewrite_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_ERR_REWRITE_NULL_INPUT:
        return r"n00b_production_rewrite: null production or null parse-tree node";
    case N00B_ERR_REWRITE_NO_BLOCK:
        return r"n00b_production_rewrite: production has no rewrite block";
    case N00B_ERR_REWRITE_NO_TEMPLATE:
        return r"n00b_production_rewrite: rewrite block missing required template: field";
    case N00B_ERR_REWRITE_UNDEFINED_CAPTURE:
        return r"n00b_production_rewrite: template references an undeclared capture";
    case N00B_ERR_REWRITE_NO_CHILD:
        return r"n00b_production_rewrite: capture's child index is out of range on the parse-tree node";
    case N00B_ERR_REWRITE_PPRINT_FAILED:
        return r"n00b_production_rewrite: subtree-mode pretty-print failed";
    default:
        return r"n00b_production_rewrite: (unknown)";
    }
}

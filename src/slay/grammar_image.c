// grammar_image.c - Build-time grammar baking + runtime materialization.
//
// WP-018: pre-compile a parsed `n00b_grammar_t` into emitted C source
// that materializes an identical grammar at runtime, skipping the BNF
// metagrammar parse. WP-020 replaced the old hand-replay image with a
// marshal blob so private grammar state stays faithful by construction.
//
// The emitter intentionally uses plain `"..."` C string literals (each
// wrapped with `n00b_string_from_cstr`) for its code templates rather
// than `r"..."` rich literals: rich literals process `\` as markup at
// ncc-compile time, which would corrupt the backslash/quote/newline
// bytes the emitted C source must contain verbatim
// (n00b-api-guidelines § 2.11 — plain format strings, not raw).

#include "slay/grammar_image.h"
#include "internal/slay/grammar_internal.h"
#include "core/string.h"
#include "text/strings/string_ops.h"
#include "text/strings/format.h"
#include "crypto/base64.h"
#include "util/marshal.h"
#include "parsers/tokenizer_registry.h"
#include <string.h>

static inline void
repair_dict_hash(_n00b_dict_internal_t *d, n00b_hash_fn fn)
{
    if (d == nullptr) {
        return;
    }

    d->fn            = fn;
    d->skip_obj_hash = true;
}

static inline void
repair_word_set(n00b_dict_t(int64_t, bool) *d)
{
    repair_dict_hash((_n00b_dict_internal_t *)d, n00b_hash_word);
}

void
n00b_grammar_image_repair(n00b_grammar_t *g)
{
    if (g == nullptr) {
        return;
    }

    // Hash callbacks are function pointers; a marshal blob produced by the
    // bake executable cannot reuse those raw code addresses in the runtime
    // executable.
    repair_dict_hash((_n00b_dict_internal_t *)g->nt_map, n00b_string_hash);
    repair_dict_hash((_n00b_dict_internal_t *)g->terminal_map, n00b_string_hash);
    repair_dict_hash((_n00b_dict_internal_t *)g->literal_type_map,
                     n00b_string_hash);
    repair_word_set(g->valid_tokens);
    repair_dict_hash((_n00b_dict_internal_t *)g->terminal_by_id,
                     n00b_hash_word);
    repair_dict_hash((_n00b_dict_internal_t *)g->terminal_categories,
                     n00b_hash_word);

    for (size_t i = 0; i < g->nt_list.len; i++) {
        n00b_nonterm_t *nt = &g->nt_list.data[i];

        repair_word_set(nt->first_set);
        nt->action = nullptr;
    }

    for (size_t i = 0; i < g->rules.len; i++) {
        n00b_parse_rule_t *rule = &g->rules.data[i];

        repair_word_set(rule->first_set);
        rule->thunk = nullptr;
    }

    g->default_action = nullptr;
    g->disambiguator  = nullptr;
    g->tokenize_cb    = nullptr;

    if (g->tokenizer_name != nullptr && g->tokenizer_name->data != nullptr) {
        bool found = false;
        g->tokenize_cb = n00b_tokenizer_lookup(g->tokenizer_name->data,
                                               &found);
        if (!found) {
            g->tokenize_cb = nullptr;
        }
    }
}

// ============================================================================
// Emitter
// ============================================================================
//
// The emitted source for c_ncc.bnf is a multi-megabyte base64 blob, so the
// emitter accumulates pieces into a list and joins once at the end rather than
// repeatedly `n00b_unicode_str_cat`-ing onto a growing string.

// Internal emitter helpers: `allocator` is the value threaded down from
// `n00b_grammar_image_emit`'s `.allocator` kwarg (nullptr = runtime
// default). It is forwarded to every `n00b_string_from_cstr` /
// `n00b_string_from_raw` / `n00b_list_new_private` allocation these
// helpers make so the whole emitted-source byte graph lives in the
// caller's chosen arena (§ 4.2).

static inline void
emit(n00b_list_t(n00b_string_t *) *parts,
     const char                   *s,
     n00b_allocator_t             *allocator)
{
    n00b_list_push(*parts, n00b_string_from_cstr(s, .allocator = allocator));
}

static inline void
emit_str(n00b_list_t(n00b_string_t *) *parts, n00b_string_t *s)
{
    n00b_list_push(*parts, s);
}

// Build a quoted C string literal (with surrounding double quotes) for
// the bytes of `s` (or "" for null), escaping whatever the C lexer cares
// about so the result is valid regardless of the name's contents.
static n00b_string_t *
c_quoted(n00b_string_t *s, n00b_allocator_t *allocator)
{
    const char *data  = (s != nullptr && s->data != nullptr) ? s->data : "";
    int64_t     bytes = (s != nullptr && s->data != nullptr) ? s->u8_bytes : 0;

    // Worst case is 4 output bytes per input byte (\\ooo), plus the two
    // surrounding quotes and a terminator.
    char  *buf = n00b_alloc_array(char, (size_t)bytes * 4 + 3,
                                  .allocator = allocator);
    size_t k   = 0;

    buf[k++] = '"';
    for (int64_t i = 0; i < bytes; i++) {
        unsigned char c = (unsigned char)data[i];
        switch (c) {
        case '\\': buf[k++] = '\\'; buf[k++] = '\\'; break;
        case '"':  buf[k++] = '\\'; buf[k++] = '"';  break;
        case '\n': buf[k++] = '\\'; buf[k++] = 'n';  break;
        case '\r': buf[k++] = '\\'; buf[k++] = 'r';  break;
        case '\t': buf[k++] = '\\'; buf[k++] = 't';  break;
        default:
            if (c >= 0x20 && c < 0x7f) {
                buf[k++] = (char)c;
            }
            else {
                buf[k++] = '\\';
                buf[k++] = (char)('0' + ((c >> 6) & 0x7));
                buf[k++] = (char)('0' + ((c >> 3) & 0x7));
                buf[k++] = (char)('0' + (c & 0x7));
            }
            break;
        }
    }
    buf[k++] = '"';
    buf[k]   = '\0';

    return n00b_string_from_raw(buf, (int64_t)k, .allocator = allocator);
}

// Push a bare double-quoted string literal body. Used to form the body of
// an r-string (`r"..."`) for the `n00b_static_grammar_register` call, which
// runs in a `[[gnu::constructor]]` BEFORE the n00b runtime: the r-string is
// a static `n00b_string_t` available pre-runtime, so register takes
// `n00b_string_t *` (no `const char *` C-ABI boundary). Grammar names are
// plain identifiers, so the C-escaped body equals the raw r-string body.
static void
emit_c_quoted(n00b_list_t(n00b_string_t *) *parts,
              n00b_string_t                *s,
              n00b_allocator_t             *allocator)
{
    n00b_list_push(*parts, c_quoted(s, allocator));
}

n00b_string_t *
n00b_grammar_image_emit_err_str(n00b_err_t err)
{
    switch ((n00b_grammar_image_err_t)err) {
    case N00B_GRAMMAR_IMAGE_OK:
        return r"ok";
    case N00B_GRAMMAR_IMAGE_ERR_NULL_ARG:
        return r"a required argument (grammar, symbol prefix, or grammar name) was null";
    case N00B_GRAMMAR_IMAGE_ERR_NOT_FINAL:
        return r"grammar is not finalized";
    case N00B_GRAMMAR_IMAGE_ERR_MARSHAL:
        return r"grammar could not be marshaled";
    case N00B_GRAMMAR_IMAGE_ERR_ENCODE:
        return r"grammar marshal bytes could not be base64-encoded";
    }

    return r"unknown grammar-image error";
}

static void
emit_c_string_chunks(n00b_list_t(n00b_string_t *) *parts,
                     n00b_string_t                *s,
                     n00b_allocator_t             *allocator)
{
    const size_t chunk = 16 * 1024;
    size_t       off   = 0;

    while (off < s->u8_bytes) {
        size_t n = s->u8_bytes - off;
        if (n > chunk) {
            n = chunk;
        }

        // Base64 uses only C-string-safe ASCII bytes, so avoid the generic
        // quoted-string path here. c_ncc.bnf emits a very large blob, and
        // 76-byte chunks force pathological allocation and GC churn.
        char *buf = n00b_alloc_array_with_opts(
            char,
            n + 8,
            &(n00b_alloc_opts_t){
                .allocator = allocator,
                .scan_kind = N00B_GC_SCAN_KIND_NONE,
            });
        size_t k = 0;
        memcpy(buf + k, "    \"", 5);
        k += 5;
        memcpy(buf + k, s->data + off, n);
        k += n;
        buf[k++] = '"';
        buf[k++] = '\n';
        buf[k]   = '\0';

        emit_str(parts,
                 n00b_string_from_raw(buf, (int64_t)k,
                                      .allocator = allocator));
        off += n;
    }
}

n00b_result_t(n00b_string_t *)
n00b_grammar_image_emit(n00b_grammar_t *g,
                        n00b_string_t  *symbol_prefix,
                        n00b_string_t  *grammar_name)
    _kargs { n00b_allocator_t *allocator = nullptr; }
{
    if (g == nullptr || symbol_prefix == nullptr || grammar_name == nullptr) {
        return n00b_result_err(n00b_string_t *,
                               N00B_GRAMMAR_IMAGE_ERR_NULL_ARG);
    }
    if (!g->finalized) {
        return n00b_result_err(n00b_string_t *,
                               N00B_GRAMMAR_IMAGE_ERR_NOT_FINAL);
    }

    n00b_list_t(n00b_string_t *) parts
        = n00b_list_new_private(n00b_string_t *, .allocator = allocator);

    n00b_marshal_ctx_t *mctx = n00b_marshal_ctx_new();
    n00b_buffer_t      *blob = n00b_marshal_incremental(mctx, g);
    if (blob == nullptr) {
        n00b_marshal_ctx_destroy(mctx);
        return n00b_result_err(n00b_string_t *,
                               N00B_GRAMMAR_IMAGE_ERR_MARSHAL);
    }
    n00b_marshal_ctx_destroy(mctx);

    auto b64_r = n00b_base64_encode(blob, .allocator = allocator);
    if (n00b_result_is_err(b64_r)) {
        return n00b_result_err(n00b_string_t *,
                               N00B_GRAMMAR_IMAGE_ERR_ENCODE);
    }
    n00b_string_t *b64 = n00b_result_get(b64_r);

    emit(&parts,
         "/* Generated by n00b_grammar_image_emit (WP-020 marshal image). "
         "Do not edit. */\n",
         allocator);
    emit(&parts, "#include \"n00b.h\"\n", allocator);
    emit(&parts, "#include \"core/static_image.h\"\n\n", allocator);
    emit(&parts, "#include \"slay/grammar_image.h\"\n", allocator);
    emit(&parts, "#include \"util/base64.h\"\n", allocator);
    emit(&parts, "#include \"util/marshal.h\"\n\n", allocator);

    emit_str(&parts,
             n00b_cformat("static const char «#»_b64[] =\n",
                          symbol_prefix));
    emit_c_string_chunks(&parts, b64, allocator);
    emit(&parts, ";\n\n", allocator);

    emit_str(&parts,
             n00b_cformat("static n00b_grammar_t *\n«#»_build(void)\n{\n",
                          symbol_prefix));
    emit_str(&parts,
             n00b_cformat("    n00b_string_t *encoded = "
                          "n00b_string_from_raw((char *)«#»_b64, "
                          "(int64_t)(sizeof(«#»_b64) - 1));\n",
                          symbol_prefix, symbol_prefix));
    emit(&parts,
         "    n00b_result_t(n00b_buffer_t *) decoded_r = "
         "n00b_base64_decode(encoded);\n"
         "    if (n00b_result_is_err(decoded_r)) {\n"
         "        return nullptr;\n"
         "    }\n"
         "    n00b_buffer_t *decoded = n00b_result_get(decoded_r);\n"
         "    n00b_grammar_t *g = (n00b_grammar_t *)n00b_unmarshal_one(decoded);\n"
         "    n00b_grammar_image_repair(g);\n"
         "    return g;\n"
         "}\n\n",
         allocator);

    // --- Registration constructor. ---
    emit_str(&parts,
             n00b_cformat("[[gnu::constructor]]\nstatic void\n"
                          "«#»_register(void)\n"
                          "{\n    n00b_static_grammar_register(",
                          symbol_prefix));
    // Emit the name as an r-string (`r"..."`): a static n00b_string_t,
    // available pre-runtime, so register takes n00b_string_t *.
    emit(&parts, "r", allocator);
    emit_c_quoted(&parts, grammar_name, allocator);
    emit_str(&parts,
             n00b_cformat(", «#»_build);\n}\n", symbol_prefix));

    n00b_string_t *source
        = n00b_unicode_str_join(n00b_string_empty(.allocator = allocator),
                                n00b_list_to_array(n00b_string_t *, parts));

    return n00b_result_ok(n00b_string_t *, source);
}

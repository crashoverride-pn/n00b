/**
 * @file embed_ffi.c
 * @brief FFI embed literal handler — parses binding declarations and
 *        generates MIR wrapper functions.
 *
 * Each binding maps a n00b function name to a C symbol.  The handler:
 * 1. Resolves the C symbol from the current process.
 * 2. Generates a MIR wrapper that accepts n00b-level parameters,
 *    performs any conversions (cstr, ptr+len), constructs a kargs
 *    struct if the C function uses _kargs, and calls the C function.
 * 3. Registers the C function address so MIR can resolve it at link
 *    time.
 */

#include "n00b.h"
#include "n00b/embed_ffi.h"
#include "n00b/embed.h"
#include "slay/codegen.h"
#include "internal/slay/codegen_internal.h"
#include "core/alloc.h"
#include "core/string.h"
#include "text/strings/format.h"         // n00b_cformat
#include "text/strings/string_convert.h" // n00b_unicode_str_to_cstr (MIR edge)
#include "core/type_info.h"
#include "parsers/scan_recipes.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include "internal/win32_sockets.h"
#else
#include <dlfcn.h>
#endif

// ============================================================================
// FFI tokenizer — handles identifiers, numbers, strings, punctuation.
// ============================================================================

static bool
ffi_tokenize(n00b_scanner_t *s)
{
    // Skip whitespace and comments.
    while (!n00b_scan_at_eof(s)) {
        uint8_t b = (uint8_t)n00b_scan_peek_byte(s, 0);

        if (b == ' ' || b == '\t' || b == '\r' || b == '\n') {
            n00b_scan_advance(s);
            continue;
        }

        if (b == '#') {
            while (!n00b_scan_at_eof(s)
                   && n00b_scan_peek_byte(s, 0) != '\n') {
                n00b_scan_advance(s);
            }
            continue;
        }

        break;
    }

    if (n00b_scan_at_eof(s)) {
        return false;
    }

    uint8_t b = (uint8_t)n00b_scan_peek_byte(s, 0);

    // Multi-char punctuation: ->, <-, ...
    if (b == '-' && n00b_scan_peek_byte(s, 1) == '>') {
        n00b_scan_mark(s);
        n00b_scan_advance_n(s, 2);
        n00b_scan_emit(s);
        return true;
    }

    if (b == '<' && n00b_scan_peek_byte(s, 1) == '-') {
        n00b_scan_mark(s);
        n00b_scan_advance_n(s, 2);
        n00b_scan_emit(s);
        return true;
    }

    if (b == '.' && n00b_scan_peek_byte(s, 1) == '.'
        && n00b_scan_peek_byte(s, 2) == '.') {
        n00b_scan_mark(s);
        n00b_scan_advance_n(s, 3);
        n00b_scan_emit(s);
        return true;
    }

    // Single-char punctuation.
    if (b == ':' || b == '=' || b == '(' || b == ')' || b == ',') {
        n00b_scan_mark(s);
        n00b_scan_advance(s);
        n00b_scan_emit(s);
        return true;
    }

    // String literals.
    if (b == '"') {
        n00b_option_t(n00b_string_t *) val = n00b_scan_string_double(s);
        n00b_scan_emit(s, .token_type = "STRING", .contents = val);
        return true;
    }

    // Number literals.
    if (b >= '0' && b <= '9') {
        if (n00b_scan_number(s, "INTEGER", "FLOAT")) {
            return true;
        }
    }

    // Identifiers and keywords — same pattern as n00b_lang_tokenize:
    // try as fixed-text first (matches grammar keywords like %"kw"),
    // fall back to IDENTIFIER literal type.
    if ((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_') {
        n00b_option_t(n00b_string_t *) id = n00b_scan_identifier(s,
                                   .allow_underscore_start = true);

        if (n00b_option_is_set(id)) {
            n00b_token_err_t err = n00b_scan_emit(s, .contents = id);

            if (err == N00B_TOK_ERR_NOT_IN_GRAMMAR) {
                n00b_scan_emit(s, .token_type = "IDENTIFIER",
                                .contents = id);
            }

            return true;
        }
    }

    // Unknown character — skip.
    n00b_scan_advance(s);
    return true;
}

// ============================================================================
// FFI BNF grammar
// ============================================================================

static const char ffi_bnf_text[] =
    "<ffi> ::= <binding>+\n"
    "\n"
    "<binding> ::= %IDENTIFIER %\":\" <signature> %\"=\" %IDENTIFIER <bind-clause>*\n"
    "\n"
    "<signature> ::= %\"(\" <param-list>? %\")\" %\"->\" <return-spec>\n"
    "\n"
    "<param-list> ::= <param> (%\",\" <param>)*\n"
    "\n"
    "<param> ::= %IDENTIFIER <conversion>?\n"
    "          | %\"...\"\n"
    "\n"
    "<conversion> ::= %\"->\" %IDENTIFIER\n"
    "               | %\"->\" %\"(\" %IDENTIFIER %\",\" %\"len\" %\")\"\n"
    "\n"
    "<return-spec> ::= %\"void\"\n"
    "                | %IDENTIFIER <ownership>?\n"
    "\n"
    "<ownership> ::= %\"<-\" %IDENTIFIER %\"owns\" <own-strategy>\n"
    "\n"
    "<own-strategy> ::= %\"caller\" | %\"static\" | %\"gc\"\n"
    "\n"
    "<bind-clause> ::= <kw-clause> | <error-clause>\n"
    "\n"
    "<kw-clause> ::= %\"kw\" %IDENTIFIER %\":\" %IDENTIFIER %\"=\" <default-val>\n"
    "\n"
    "<error-clause> ::= %\"error\" <literal> %\"errno\"\n"
    "\n"
    "<default-val> ::= %INTEGER | %FLOAT | %STRING\n"
    "                | %\"true\" | %\"false\" | %\"null\"\n"
    "\n"
    "<literal> ::= %INTEGER | %FLOAT | %STRING\n"
;

n00b_string_t *
n00b_ffi_bnf(void)
{
    return n00b_string_from_cstr(ffi_bnf_text);
}

// ============================================================================
// Parse tree helpers
// ============================================================================

static n00b_string_t *
extract_id(n00b_parse_tree_t *node)
{
    if (!node) {
        return nullptr;
    }

    n00b_parse_tree_t *tok = n00b_pt_first_token(node);

    if (!tok) {
        tok = node;
    }

    const char *text = n00b_pt_token_text(tok);
    size_t      tlen = n00b_pt_token_text_len(tok);

    if (!text || tlen == 0) {
        return nullptr;
    }

    return n00b_string_from_raw(text, (int64_t)tlen);
}

static void
ffi_collect_tokens(n00b_parse_tree_t  *node,
                   n00b_parse_tree_t **out,
                   int32_t             max,
                   int32_t            *count)
{
    if (!node || !out || !count || *count >= max) {
        return;
    }

    if (n00b_pt_is_token(node)) {
        out[(*count)++] = node;
        return;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc && *count < max; i++) {
        ffi_collect_tokens(n00b_pt_get_child(node, i), out, max, count);
    }
}

// ============================================================================
// FFI binding representation
// ============================================================================

typedef enum {
    FFI_CONV_NONE,       // Pass directly (integers, pointers).
    FFI_CONV_CSTR,       // string -> null-terminated char*.
    FFI_CONV_PTR_LEN,    // buffer/array/string -> (ptr, len) pair.
    FFI_CONV_VARARGS,    // ...
} ffi_conv_kind_t;

typedef struct {
    n00b_string_t  *n00b_type;
    n00b_string_t  *c_type;
    ffi_conv_kind_t conv;
} ffi_param_t;

typedef enum {
    FFI_OWN_NONE,
    FFI_OWN_CALLER,
    FFI_OWN_STATIC,
    FFI_OWN_GC,
} ffi_own_t;

typedef struct {
    n00b_string_t *n00b_type;
    n00b_string_t *c_type;
    ffi_own_t      ownership;
    bool           is_void;
} ffi_return_t;

typedef struct {
    n00b_string_t *name;
    n00b_string_t *type;
    n00b_string_t *default_val;
} ffi_kwarg_t;

typedef struct {
    n00b_string_t *n00b_name;
    n00b_string_t *c_name;
    ffi_param_t   *params;
    int32_t        param_count;
    ffi_return_t   ret;
    ffi_kwarg_t   *kwargs;
    int32_t        kwarg_count;
    bool           has_varargs;
} ffi_binding_t;

// ============================================================================
// Parse tree → ffi_binding_t
// ============================================================================

static ffi_conv_kind_t
parse_conversion(n00b_parse_tree_t *conv_node)
{
    if (!conv_node) {
        return FFI_CONV_NONE;
    }

    // Check for (ptr, len) form.
    n00b_parse_tree_t *paren = n00b_pt_find_child_by_token(conv_node, "(");

    if (paren) {
        return FFI_CONV_PTR_LEN;
    }

    // Simple -> c_type: check for "cstr".
    size_t nch = n00b_pt_num_children(conv_node);

    for (size_t i = 0; i < nch; i++) {
        n00b_parse_tree_t *ch = n00b_pt_get_child(conv_node, i);

        if (n00b_pt_is_token(ch)) {
            const char *txt = n00b_pt_token_text(ch);
            size_t      len = n00b_pt_token_text_len(ch);

            if (txt && len == 4 && memcmp(txt, "cstr", 4) == 0) {
                return FFI_CONV_CSTR;
            }
        }
    }

    return FFI_CONV_NONE;
}

static ffi_param_t
parse_param(n00b_parse_tree_t *param_node)
{
    ffi_param_t p = {0};

    n00b_parse_tree_t *dots = n00b_pt_find_child_by_token(param_node, "...");

    if (dots) {
        p.conv = FFI_CONV_VARARGS;
        return p;
    }

    n00b_parse_tree_t *first_tok = n00b_pt_first_token(param_node);
    p.n00b_type = extract_id(first_tok);

    n00b_parse_tree_t *conv = n00b_pt_find_child_by_nt(param_node,
                                                         "conversion");
    p.conv = parse_conversion(conv);

    if (p.conv == FFI_CONV_CSTR || p.conv == FFI_CONV_PTR_LEN) {
        size_t nch = n00b_pt_num_children(conv);

        for (size_t i = 0; i < nch; i++) {
            n00b_parse_tree_t *ch = n00b_pt_get_child(conv, i);

            if (n00b_pt_is_token(ch)) {
                const char *txt = n00b_pt_token_text(ch);
                size_t      len = n00b_pt_token_text_len(ch);

                if (txt && len > 0 && txt[0] != '-' && txt[0] != '('
                    && txt[0] != ')' && txt[0] != ',') {
                    p.c_type = n00b_string_from_raw(txt, (int64_t)len);
                    break;
                }
            }
        }
    }

    return p;
}

static ffi_return_t
parse_return_spec(n00b_parse_tree_t *ret_node)
{
    ffi_return_t r = {0};

    if (!ret_node) {
        r.is_void = true;
        return r;
    }

    n00b_parse_tree_t *void_tok = n00b_pt_find_child_by_token(ret_node,
                                                                "void");
    if (void_tok) {
        r.is_void = true;
        return r;
    }

    r.n00b_type = extract_id(n00b_pt_first_token(ret_node));

    n00b_parse_tree_t *own_node = n00b_pt_find_child_by_nt(ret_node,
                                                             "ownership");
    if (own_node) {
        size_t nch = n00b_pt_num_children(own_node);

        for (size_t i = 0; i < nch; i++) {
            n00b_parse_tree_t *ch = n00b_pt_get_child(own_node, i);

            if (n00b_pt_is_token(ch)) {
                const char *txt = n00b_pt_token_text(ch);
                size_t      len = n00b_pt_token_text_len(ch);

                if (txt && len > 0 && txt[0] != '<') {
                    r.c_type = n00b_string_from_raw(txt, (int64_t)len);
                    break;
                }
            }
        }

        n00b_parse_tree_t *strat = n00b_pt_find_child_by_nt(
            own_node, "own-strategy");

        if (strat) {
            const char *txt = n00b_pt_token_text(n00b_pt_first_token(strat));
            size_t      len = n00b_pt_token_text_len(
                n00b_pt_first_token(strat));

            if (txt) {
                if (len == 6 && memcmp(txt, "caller", 6) == 0) {
                    r.ownership = FFI_OWN_CALLER;
                }
                else if (len == 6 && memcmp(txt, "static", 6) == 0) {
                    r.ownership = FFI_OWN_STATIC;
                }
                else if (len == 2 && memcmp(txt, "gc", 2) == 0) {
                    r.ownership = FFI_OWN_GC;
                }
            }
        }
    }

    return r;
}

static ffi_binding_t
parse_binding(n00b_parse_tree_t *bind_node)
{
    ffi_binding_t b = {0};

    size_t nc = n00b_pt_num_children(bind_node);
    int id_idx = 0;

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *ch = n00b_pt_get_child(bind_node, i);

        if (n00b_pt_is_token(ch)) {
            const char *txt = n00b_pt_token_text(ch);
            size_t      len = n00b_pt_token_text_len(ch);

            if (txt && len > 0 && txt[0] != ':' && txt[0] != '=') {
                if (id_idx == 0) {
                    b.n00b_name = n00b_string_from_raw(txt, (int64_t)len);
                }
                else if (id_idx == 1) {
                    b.c_name = n00b_string_from_raw(txt, (int64_t)len);
                }
                id_idx++;
            }
        }
    }

    n00b_parse_tree_t *sig = n00b_pt_find_child_by_nt(bind_node, "signature");

    if (sig) {
        // Collect <param> nodes from the signature.  The <param-list>
        // NT may be eliminated by single-child optimization or wrapped
        // in a group node from the `?` quantifier, so search the whole
        // signature subtree instead of looking for param-list first.
        n00b_parse_tree_t *params[64];
        int np = n00b_pt_collect_nt_deep(sig, "param", params, 64);

        if (np > 0) {
            b.params      = n00b_alloc_array(ffi_param_t, np);
            b.param_count = np;

            for (int i = 0; i < np; i++) {
                b.params[i] = parse_param(params[i]);

                if (b.params[i].conv == FFI_CONV_VARARGS) {
                    b.has_varargs = true;
                }
            }
        }
        else {
            // If no <param> NTs found (possibly eliminated too),
            // check if there are bare IDENTIFIER tokens between
            // '(' and ')' that represent params.
            n00b_parse_tree_t *sig_tokens[128];
            int32_t            sig_ntokens = 0;
            bool               in_pl       = false;
            bool               in_conv     = false;
            ffi_param_t        fallback[64];
            int32_t     fallback_n = 0;

            ffi_collect_tokens(sig, sig_tokens, 128, &sig_ntokens);

            for (int32_t si = 0; si < sig_ntokens && fallback_n < 64; si++) {
                const char *t = n00b_pt_token_text(sig_tokens[si]);
                size_t      l = n00b_pt_token_text_len(sig_tokens[si]);

                if (!t || l == 0) {
                    continue;
                }

                if (l == 1 && t[0] == '(') {
                    in_pl = true;
                    continue;
                }
                if (l == 1 && t[0] == ')') {
                    break;
                }
                if (!in_pl || (l == 1 && (t[0] == ',' || t[0] == ':'))) {
                    continue;
                }
                if (l == 2 && memcmp(t, "->", 2) == 0) {
                    in_conv = true;
                    continue;
                }
                if (l == 3 && memcmp(t, "len", 3) == 0) {
                    continue;
                }

                if (in_conv && fallback_n > 0) {
                    ffi_param_t *p = &fallback[fallback_n - 1];

                    if (l == 4 && memcmp(t, "cstr", 4) == 0) {
                        p->conv   = FFI_CONV_CSTR;
                        p->c_type = n00b_string_from_cstr("cstr");
                    }
                    else if (l == 3 && memcmp(t, "ptr", 3) == 0) {
                        p->conv   = FFI_CONV_PTR_LEN;
                        p->c_type = n00b_string_from_cstr("ptr");
                    }

                    in_conv = false;
                    continue;
                }

                fallback[fallback_n++] = (ffi_param_t){
                    .n00b_type = n00b_string_from_raw(t, (int64_t)l),
                    .c_type    = NULL,
                    .conv      = FFI_CONV_NONE,
                };
            }

            if (fallback_n > 0) {
                b.params      = n00b_alloc_array(ffi_param_t, (size_t)fallback_n);
                b.param_count = fallback_n;

                for (int32_t i = 0; i < fallback_n; i++) {
                    b.params[i] = fallback[i];
                }
            }
        }

        n00b_parse_tree_t *ret = n00b_pt_find_child_by_nt(sig,
                                                            "return-spec");
        b.ret = parse_return_spec(ret);
    }

    // Parse kw-clauses.
    // The grammar has <bind-clause>* which creates a group node.
    // <bind-clause> ::= <kw-clause> | ... — bind-clause may not be
    // eliminated (has alternatives), so collect bind-clause first,
    // then look inside each for kw-clause.
    n00b_parse_tree_t *clauses[32];
    int nclauses = n00b_pt_collect_nt_deep(bind_node, "kw-clause",
                                            clauses, 32);

    if (nclauses == 0) {
        // Try via bind-clause (kw-clause wrapped in non-eliminated NT).
        n00b_parse_tree_t *bc[32];
        int nbc = n00b_pt_collect_nt_deep(bind_node, "bind-clause", bc, 32);

        for (int i = 0; i < nbc && nclauses < 32; i++) {
            n00b_parse_tree_t *kc = n00b_pt_find_child_by_nt(bc[i], "kw-clause");
            if (kc) {
                clauses[nclauses++] = kc;
            }
        }
    }


    if (nclauses > 0) {
        b.kwargs      = n00b_alloc_array(ffi_kwarg_t, nclauses);
        b.kwarg_count = nclauses;

        for (int i = 0; i < nclauses; i++) {
            int kid = 0;

            size_t nch = n00b_pt_num_children(clauses[i]);

            for (size_t j = 0; j < nch; j++) {
                n00b_parse_tree_t *ch = n00b_pt_get_child(clauses[i], j);

                if (n00b_pt_is_token(ch)) {
                    const char *txt = n00b_pt_token_text(ch);
                    size_t      len = n00b_pt_token_text_len(ch);

                    if (txt && len > 0 && txt[0] != ':' && txt[0] != '='
                        && !(len == 2 && memcmp(txt, "kw", 2) == 0)) {
                        if (kid == 0) {
                            b.kwargs[i].name =
                                n00b_string_from_raw(txt, (int64_t)len);
                        }
                        else if (kid == 1) {
                            b.kwargs[i].type =
                                n00b_string_from_raw(txt, (int64_t)len);
                        }
                        kid++;
                    }
                }
            }

            n00b_parse_tree_t *dv = n00b_pt_find_child_by_nt(
                clauses[i], "default-val");

            if (dv) {
                b.kwargs[i].default_val = extract_id(dv);
            }
        }
    }

    return b;
}

// ============================================================================
// Type helpers
// ============================================================================

static MIR_type_t
ffi_mir_type(n00b_string_t *type_name)
{
    if (!type_name) {
        return MIR_T_I64;
    }

    const char *t = type_name->data;
    size_t      n = type_name->u8_bytes;

    if ((n == 3 && memcmp(t, "i64", 3) == 0)
        || (n == 3 && memcmp(t, "int", 3) == 0)) {
        return MIR_T_I64;
    }

    if (n == 3 && memcmp(t, "i32", 3) == 0) {
        return MIR_T_I32;
    }

    if (n == 3 && memcmp(t, "u32", 3) == 0) {
        return MIR_T_U32;
    }

    if (n == 3 && memcmp(t, "u64", 3) == 0) {
        return MIR_T_U64;
    }

    if (n == 3 && memcmp(t, "f64", 3) == 0) {
        return MIR_T_D;
    }

    if (n == 3 && memcmp(t, "f32", 3) == 0) {
        return MIR_T_F;
    }

    if (n == 4 && memcmp(t, "bool", 4) == 0) {
        return MIR_T_I64;
    }

    if (n == 2 && memcmp(t, "i8", 2) == 0) {
        return MIR_T_I8;
    }

    if (n == 2 && memcmp(t, "u8", 2) == 0) {
        return MIR_T_U8;
    }

    if (n == 3 && memcmp(t, "i16", 3) == 0) {
        return MIR_T_I16;
    }

    if (n == 3 && memcmp(t, "u16", 3) == 0) {
        return MIR_T_U16;
    }

    // Pointer-like values are carried as 64-bit words in this MIR backend.
    return MIR_T_I64;
}

// Size of a kargs field in bytes based on its FFI type name.
static size_t
ffi_kw_field_size(n00b_string_t *type_name)
{
    if (!type_name) {
        return 8; // Default to pointer size.
    }

    const char *t = type_name->data;
    size_t      n = type_name->u8_bytes;

    if (n == 4 && memcmp(t, "bool", 4) == 0) {
        return 1;
    }

    if (n == 2 && (memcmp(t, "i8", 2) == 0 || memcmp(t, "u8", 2) == 0)) {
        return 1;
    }

    if (n == 3 && (memcmp(t, "i16", 3) == 0 || memcmp(t, "u16", 3) == 0)) {
        return 2;
    }

    if (n == 3 && (memcmp(t, "i32", 3) == 0 || memcmp(t, "u32", 3) == 0
                   || memcmp(t, "f32", 3) == 0)) {
        return 4;
    }

    if (n == 6 && memcmp(t, "option", 6) == 0) {
        return 16; // n00b_option_t(T) = { bool has_value; T value; }
    }

    // Everything else (i64, u64, f64, int, ptr, string, etc.) = 8.
    return 8;
}

// Alignment of a kargs field.
static size_t
ffi_kw_field_align(n00b_string_t *type_name)
{
    size_t sz = ffi_kw_field_size(type_name);

    // option is 16 bytes but aligned to 8 (its largest member is a pointer).
    if (sz == 16 && type_name && type_name->u8_bytes == 6
        && memcmp(type_name->data, "option", 6) == 0) {
        return 8;
    }

    return sz;
}

static size_t
align_up(size_t val, size_t alignment)
{
    return (val + alignment - 1) & ~(alignment - 1);
}

// ============================================================================
// Kargs struct layout computation
// ============================================================================

typedef struct {
    size_t  bitfield_bytes;  // Size of the _has_* bitfield section.
    size_t *field_offsets;   // Byte offset of each kw field in the struct.
    size_t  total_size;      // Total struct size (with padding).
} kargs_layout_t;

// Compute the layout of a kargs struct matching ncc's ABI:
//   struct _func__kargs {
//       unsigned _has_field0 : 1;
//       unsigned _has_field1 : 1;
//       ...
//       type0 field0;
//       type1 field1;
//       ...
//   };
//
// The bitfields are packed by the C compiler into unsigned int units.
// On most ABIs, the bitfield section occupies ceil(n_fields / 32) * 4
// bytes (unsigned is 4 bytes with one bit per field).
static kargs_layout_t
compute_kargs_layout(ffi_kwarg_t *kwargs, int32_t kwarg_count)
{
    kargs_layout_t layout = {0};

    if (kwarg_count == 0) {
        return layout;
    }

    layout.field_offsets = n00b_alloc_array(size_t, kwarg_count);

    // Bitfields: ncc uses `unsigned _has_X : 1` for each.
    // The C compiler packs these into `unsigned` (4-byte) units.
    // Each unsigned holds 32 bits.
    size_t n_unsigned_units = ((size_t)kwarg_count + 31) / 32;
    layout.bitfield_bytes = n_unsigned_units * 4;

    // Fields follow the bitfield section.
    size_t offset = layout.bitfield_bytes;

    for (int32_t i = 0; i < kwarg_count; i++) {
        size_t sz    = ffi_kw_field_size(kwargs[i].type);
        size_t al    = ffi_kw_field_align(kwargs[i].type);
        offset       = align_up(offset, al);
        layout.field_offsets[i] = offset;
        offset      += sz;
    }

    // Final padding to max alignment.
    size_t max_align = 8; // Pointer alignment.
    layout.total_size = align_up(offset, max_align);

    return layout;
}

// ============================================================================
// Default value parsing
// ============================================================================

static int64_t
parse_default_int(n00b_string_t *val)
{
    if (!val) {
        return 0;
    }

    const char *s = val->data;
    size_t      n = val->u8_bytes;

    if (n == 4 && memcmp(s, "true", 4) == 0)  return 1;
    if (n == 5 && memcmp(s, "false", 5) == 0) return 0;
    if (n == 4 && memcmp(s, "null", 4) == 0)  return 0;

    // Numeric.
    char buf[64];
    size_t copy = n < 63 ? n : 63;
    memcpy(buf, s, copy);
    buf[copy] = '\0';

    return strtol(buf, nullptr, 0);
}

// ============================================================================
// String helper: n00b_string_t* to null-terminated C string.
// ============================================================================

static const char *
str_cstr(n00b_string_t *s, char *buf, size_t bufsz)
{
    if (!s || s->u8_bytes == 0) {
        buf[0] = '\0';
        return buf;
    }

    size_t copy = s->u8_bytes < bufsz - 1 ? s->u8_bytes : bufsz - 1;
    memcpy(buf, s->data, copy);
    buf[copy] = '\0';
    return buf;
}

static void *
lookup_process_symbol(const char *name)
{
#ifdef _WIN32
    const char *delim = strchr(name, '!');
    if (!delim) {
        delim = strchr(name, ':');
    }

    if (delim && delim != name && delim[1] != '\0') {
        char module_name[260];
        size_t module_len = (size_t)(delim - name);
        if (module_len >= sizeof(module_name)) {
            module_len = sizeof(module_name) - 1;
        }
        memcpy(module_name, name, module_len);
        module_name[module_len] = '\0';

        HMODULE module = GetModuleHandleA(module_name);
        if (!module) {
            module = LoadLibraryA(module_name);
        }
        return module ? (void *)GetProcAddress(module, delim + 1) : nullptr;
    }

    HMODULE main_module = GetModuleHandleA(nullptr);
    if (main_module) {
        FARPROC proc = GetProcAddress(main_module, name);
        if (proc) {
            return (void *)proc;
        }
    }

    static const char *default_modules[] = {
        "n00b.dll",
        "libn00b.dll",
        "ucrtbase.dll",
        "msvcrt.dll",
        "kernel32.dll",
        nullptr,
    };

    for (int i = 0; default_modules[i]; i++) {
        HMODULE module = GetModuleHandleA(default_modules[i]);
        if (!module) {
            continue;
        }
        FARPROC proc = GetProcAddress(module, name);
        if (proc) {
            return (void *)proc;
        }
    }

    return nullptr;
#else
    return dlsym(RTLD_DEFAULT, name);
#endif
}

// ============================================================================
// MIR wrapper generation
// ============================================================================

static bool
generate_wrapper(n00b_cg_session_t *s, ffi_binding_t *b)
{
    n00b_cg_module_t *m = s->active_module;

    if (!m) {
        fprintf(stderr, "ffi: no active module for wrapper generation\n");
        return false;
    }

    char n00b_name_buf[256];
    char c_name_buf[256];

    str_cstr(b->n00b_name, n00b_name_buf, sizeof(n00b_name_buf));
    str_cstr(b->c_name, c_name_buf, sizeof(c_name_buf));

    size_t n00b_name_len = strlen(n00b_name_buf);
    size_t c_name_len    = strlen(c_name_buf);
    char  *n00b_name     = n00b_alloc_array(char, n00b_name_len + 1);
    char  *c_name        = n00b_alloc_array(char, c_name_len + 1);

    memcpy(n00b_name, n00b_name_buf, n00b_name_len + 1);
    memcpy(c_name, c_name_buf, c_name_len + 1);

    // MIR import name: char* only at the MIR symbol edge.
    char *import_name = n00b_unicode_str_to_cstr(
        n00b_cformat("__n00b_ffi_import_[|#|]_[|#|]",
                     n00b_string_from_cstr(n00b_name),
                     n00b_string_from_cstr(c_name)));

    // Resolve the C function address.
    void *c_addr = lookup_process_symbol(c_name);

    if (!c_addr) {
#ifdef _WIN32
        fprintf(stderr, "ffi: GetProcAddress failed for '%s'\n",
                c_name);
#else
        fprintf(stderr, "ffi: dlsym failed for '%s': %s\n",
                c_name, dlerror());
#endif
        return false;
    }

    // Count C-level parameters (conversions expand n00b params).
    int c_param_count = 0;

    for (int i = 0; i < b->param_count; i++) {
        if (b->params[i].conv == FFI_CONV_PTR_LEN) {
            c_param_count += 2;
        }
        else if (b->params[i].conv != FFI_CONV_VARARGS) {
            c_param_count++;
        }
    }

    // Add trailing kargs pointer if this function has kargs.
    bool has_kargs = (b->kwarg_count > 0);
    if (has_kargs) {
        c_param_count++;
    }

    MIR_type_t ret_type = b->ret.is_void ? MIR_T_I64
                                         : ffi_mir_type(b->ret.n00b_type);

    // ----------------------------------------------------------------
    // Import the C function symbol.
    // ----------------------------------------------------------------
    MIR_item_t c_import = MIR_new_import(s->mir_ctx, import_name);

    // Also register the address in the module's import table so
    // MIR_load_external() can resolve it at link time.
    if (m->import_count >= m->import_cap) {
        int32_t new_cap = m->import_cap ? m->import_cap * 2 : 16;
        n00b_cg_import_t *new_imports = n00b_alloc_array(
            n00b_cg_import_t, (size_t)new_cap);
        if (m->imports) {
            memcpy(new_imports, m->imports,
                   sizeof(n00b_cg_import_t) * (size_t)m->import_count);
        }
        m->imports    = new_imports;
        m->import_cap = new_cap;
    }

    m->imports[m->import_count++] = (n00b_cg_import_t){
        .name   = import_name,
        .proto  = nullptr,  // Filled below.
        .import = c_import,
        .addr   = c_addr,
    };

    n00b_cg_import_t *imp = &m->imports[m->import_count - 1];

    // ----------------------------------------------------------------
    // Build the wrapper function.
    //
    // The wrapper accepts n00b-level params (one per declared param,
    // not expanded), performs conversions, constructs the kargs struct,
    // and calls the C function.
    // ----------------------------------------------------------------

    // Wrapper function parameters: n00b positional params only.
    MIR_var_t *vars = n00b_alloc_array(MIR_var_t, b->param_count + 1);
    int        vi   = 0;

    for (int i = 0; i < b->param_count; i++) {
        char *pn = n00b_unicode_str_to_cstr(n00b_cformat("p[|#|]", (int64_t)i));

        if (b->params[i].conv == FFI_CONV_VARARGS) {
            vars[vi] = (MIR_var_t){.type = MIR_T_I64, .name = "vargs"};
        }
        else {
            vars[vi] = (MIR_var_t){
                .type = ffi_mir_type(b->params[i].n00b_type),
                .name = pn};
        }
        vi++;
    }

    MIR_item_t wrapper;

    if (b->ret.is_void) {
        wrapper = MIR_new_func_arr(s->mir_ctx, n00b_name,
                                    0, nullptr, vi, vars);
    }
    else {
        MIR_type_t rets[] = {ret_type};
        wrapper = MIR_new_func_arr(s->mir_ctx, n00b_name,
                                    1, rets, vi, vars);
    }

    MIR_func_t wfunc = wrapper->u.func;

    // ----------------------------------------------------------------
    // Build the C-side call prototype.
    // ----------------------------------------------------------------
    MIR_var_t *c_vars = n00b_alloc_array(MIR_var_t, c_param_count + 1);
    int        ci     = 0;

    for (int i = 0; i < b->param_count; i++) {
        char *name_copy = n00b_unicode_str_to_cstr(
            n00b_cformat("cp[|#|]", (int64_t)ci));

        if (b->params[i].conv == FFI_CONV_PTR_LEN) {
            c_vars[ci++] = (MIR_var_t){.type = MIR_T_I64, .name = "ptr"};
            c_vars[ci++] = (MIR_var_t){.type = MIR_T_I64, .name = "len"};
        }
        else if (b->params[i].conv == FFI_CONV_CSTR) {
            c_vars[ci++] = (MIR_var_t){.type = MIR_T_I64, .name = name_copy};
        }
        else if (b->params[i].conv != FFI_CONV_VARARGS) {
            c_vars[ci++] = (MIR_var_t){
                .type = ffi_mir_type(b->params[i].n00b_type),
                .name = name_copy};
        }
    }

    if (has_kargs) {
        c_vars[ci++] = (MIR_var_t){.type = MIR_T_I64, .name = "kargs"};
    }

    MIR_type_t *c_res_types = nullptr;
    int          c_res_n     = 0;

    if (!b->ret.is_void) {
        c_res_types = &ret_type;
        c_res_n     = 1;
    }

    char *proto_name = n00b_unicode_str_to_cstr(
        n00b_cformat("__[|#|]_proto", n00b_string_from_cstr(n00b_name)));

    MIR_item_t proto = MIR_new_proto_arr(s->mir_ctx, proto_name,
                                          c_res_n, c_res_types,
                                          ci, c_vars);

    imp->proto = proto;

    // ----------------------------------------------------------------
    // Emit MIR instructions for the wrapper body.
    // ----------------------------------------------------------------

    // Kargs struct construction via ALLOCA + stores.
    MIR_reg_t kargs_reg = 0;
    kargs_layout_t kl   = {0};

    if (has_kargs) {
        kl = compute_kargs_layout(b->kwargs, b->kwarg_count);

        // Allocate the kargs struct on the stack.
        kargs_reg = MIR_new_func_reg(s->mir_ctx, wfunc, MIR_T_I64,
                                      "kargs_mem");

        MIR_append_insn(s->mir_ctx, wrapper,
            MIR_new_insn(s->mir_ctx, MIR_ALLOCA,
                MIR_new_reg_op(s->mir_ctx, kargs_reg),
                MIR_new_int_op(s->mir_ctx, (int64_t)kl.total_size)));

        // Zero the entire struct (clears all _has_ bits to 0, all
        // fields to zero-default).  We use a series of 8-byte MOVs.
        for (size_t off = 0; off < kl.total_size; off += 8) {
            MIR_append_insn(s->mir_ctx, wrapper,
                MIR_new_insn(s->mir_ctx, MIR_MOV,
                    MIR_new_mem_op(s->mir_ctx, MIR_T_I64,
                                    (MIR_disp_t)off, kargs_reg, 0, 1),
                    MIR_new_int_op(s->mir_ctx, 0)));
        }

        // Store default values for each kw field.
        for (int32_t i = 0; i < b->kwarg_count; i++) {
            int64_t def = parse_default_int(b->kwargs[i].default_val);

            if (def != 0) {
                size_t   fsz = ffi_kw_field_size(b->kwargs[i].type);
                MIR_type_t mt;

                switch (fsz) {
                case 1:  mt = MIR_T_I8;  break;
                case 2:  mt = MIR_T_I16; break;
                case 4:  mt = MIR_T_I32; break;
                default: mt = MIR_T_I64; break;
                }

                MIR_append_insn(s->mir_ctx, wrapper,
                    MIR_new_insn(s->mir_ctx, MIR_MOV,
                        MIR_new_mem_op(s->mir_ctx, mt,
                            (MIR_disp_t)kl.field_offsets[i],
                            kargs_reg, 0, 1),
                        MIR_new_int_op(s->mir_ctx, def)));
            }
        }
    }

    // ----------------------------------------------------------------
    // Build the CALL instruction operands.
    // Format: proto, func_addr, [result_reg,] c_args...
    // ----------------------------------------------------------------

    int n_call_ops = 2 + (b->ret.is_void ? 0 : 1) + ci;
    MIR_op_t *ops  = n00b_alloc_array(MIR_op_t, n_call_ops);
    int       oi   = 0;

    ops[oi++] = MIR_new_ref_op(s->mir_ctx, proto);
    ops[oi++] = MIR_new_ref_op(s->mir_ctx, c_import);

    MIR_reg_t ret_reg = 0;

    if (!b->ret.is_void) {
        ret_reg    = MIR_new_func_reg(s->mir_ctx, wfunc, ret_type, "retval");
        ops[oi++]  = MIR_new_reg_op(s->mir_ctx, ret_reg);
    }

    // Emit C-level args with conversions.
    for (int i = 0; i < b->param_count; i++) {
        if (b->params[i].conv == FFI_CONV_VARARGS) {
            continue;
        }

        MIR_reg_t preg = MIR_reg(s->mir_ctx, vars[i].name, wfunc);

        switch (b->params[i].conv) {
        case FFI_CONV_CSTR: {
            // n00b_string_t* -> char*: load the data pointer field.
            size_t data_off = offsetof(n00b_string_t, data);

            MIR_reg_t cstr_reg = MIR_new_func_reg(s->mir_ctx, wfunc,
                                                     MIR_T_I64, "cstr_tmp");
            MIR_append_insn(s->mir_ctx, wrapper,
                MIR_new_insn(s->mir_ctx, MIR_MOV,
                    MIR_new_reg_op(s->mir_ctx, cstr_reg),
                    MIR_new_mem_op(s->mir_ctx, MIR_T_I64,
                                    (MIR_disp_t)data_off,
                                    preg, 0, 1)));

            ops[oi++] = MIR_new_reg_op(s->mir_ctx, cstr_reg);
            break;
        }

        case FFI_CONV_PTR_LEN: {
            // n00b_string_t* or n00b_buffer_t* -> (ptr, len) pair.
            size_t data_off   = offsetof(n00b_string_t, data);
            size_t bytes_off  = offsetof(n00b_string_t, u8_bytes);

            MIR_reg_t ptr_reg = MIR_new_func_reg(s->mir_ctx, wfunc,
                                                    MIR_T_I64, "ptr_tmp");
            MIR_reg_t len_reg = MIR_new_func_reg(s->mir_ctx, wfunc,
                                                    MIR_T_I64, "len_tmp");

            MIR_append_insn(s->mir_ctx, wrapper,
                MIR_new_insn(s->mir_ctx, MIR_MOV,
                    MIR_new_reg_op(s->mir_ctx, ptr_reg),
                    MIR_new_mem_op(s->mir_ctx, MIR_T_I64,
                                    (MIR_disp_t)data_off,
                                    preg, 0, 1)));

            // len_tmp = obj->u8_bytes (load from memory)
            MIR_append_insn(s->mir_ctx, wrapper,
                MIR_new_insn(s->mir_ctx, MIR_MOV,
                    MIR_new_reg_op(s->mir_ctx, len_reg),
                    MIR_new_mem_op(s->mir_ctx, MIR_T_I64,
                                    (MIR_disp_t)bytes_off,
                                    preg, 0, 1)));

            ops[oi++] = MIR_new_reg_op(s->mir_ctx, ptr_reg);
            ops[oi++] = MIR_new_reg_op(s->mir_ctx, len_reg);
            break;
        }

        default:
            // Direct pass-through.
            ops[oi++] = MIR_new_reg_op(s->mir_ctx, preg);
            break;
        }
    }

    // Append kargs pointer as the last C argument.
    if (has_kargs) {
        ops[oi++] = MIR_new_reg_op(s->mir_ctx, kargs_reg);
    }

    // Emit the CALL.
    MIR_append_insn(s->mir_ctx, wrapper,
                     MIR_new_insn_arr(s->mir_ctx, MIR_CALL, oi, ops));

    // Return.
    if (!b->ret.is_void) {
        MIR_append_insn(s->mir_ctx, wrapper,
                         MIR_new_ret_insn(s->mir_ctx, 1,
                                           MIR_new_reg_op(s->mir_ctx,
                                                           ret_reg)));
    }
    else {
        MIR_append_insn(s->mir_ctx, wrapper,
                         MIR_new_ret_insn(s->mir_ctx, 0));
    }

    MIR_finish_func(s->mir_ctx);
    return true;
}

static bool
ffi_type_is(const char *type, const char *want)
{
    return type && want && strcmp(type, want) == 0;
}

static ffi_param_t
ffi_param_from_extern_type(const char *type)
{
    ffi_param_t p = {0};

    if (ffi_type_is(type, "cstring")) {
        p.n00b_type = n00b_string_from_cstr("string");
        p.c_type    = n00b_string_from_cstr("cstr");
        p.conv      = FFI_CONV_CSTR;
        return p;
    }

    if (ffi_type_is(type, "cint")) {
        type = "int";
    }
    else if (ffi_type_is(type, "csize_t")) {
        type = "u64";
    }
    else if (!type || ffi_type_is(type, "cvoid")) {
        type = "void";
    }

    p.n00b_type = n00b_string_from_cstr(type);
    p.c_type    = n00b_string_from_cstr(type);
    p.conv      = FFI_CONV_NONE;
    return p;
}

static ffi_return_t
ffi_return_from_extern_type(const char *type)
{
    ffi_return_t r = {0};

    if (!type || ffi_type_is(type, "void") || ffi_type_is(type, "cvoid")) {
        r.n00b_type = n00b_string_from_cstr("void");
        r.c_type    = n00b_string_from_cstr("void");
        r.is_void   = true;
        return r;
    }

    if (ffi_type_is(type, "cstring")) {
        type = "ptr";
    }
    else if (ffi_type_is(type, "cint")) {
        type = "int";
    }
    else if (ffi_type_is(type, "csize_t")) {
        type = "u64";
    }

    r.n00b_type = n00b_string_from_cstr(type);
    r.c_type    = n00b_string_from_cstr(type);
    r.is_void   = false;
    return r;
}

bool
n00b_ffi_install_simple(n00b_cg_session_t *session,
                        const char        *n00b_name,
                        const char        *c_name,
                        const char       **param_types,
                        int32_t            param_count,
                        const char        *ret_type)
{
    if (!session || !n00b_name || n00b_name[0] == '\0') {
        return false;
    }

    ffi_binding_t b = {0};

    b.n00b_name = n00b_string_from_cstr(n00b_name);
    b.c_name    = n00b_string_from_cstr(c_name && c_name[0] ? c_name : n00b_name);
    b.ret       = ffi_return_from_extern_type(ret_type);

    if (param_count > 0) {
        b.params = n00b_alloc_array(ffi_param_t, (size_t)param_count);

        for (int32_t i = 0; i < param_count; i++) {
            b.params[i] = ffi_param_from_extern_type(param_types ? param_types[i] : "int");
        }
    }

    b.param_count = param_count;

    return generate_wrapper(session, &b);
}

// ============================================================================
// Handler callback — returns an n00b_ffi_module_t with parsed bindings
// ============================================================================

static n00b_embed_result_t
ffi_handler(n00b_cg_session_t  *session,
            n00b_embed_input_t  input,
            void               *user_data)
{
    (void)user_data;

    n00b_embed_result_t void_result = {0};

    if (!n00b_variant_is_type(input, n00b_parse_tree_t *)) {
        fprintf(stderr, "ffi: expected parse tree input\n");
        return void_result;
    }

    n00b_parse_tree_t *tree = n00b_variant_get(input, n00b_parse_tree_t *);

    n00b_parse_tree_t *bind_nodes[256];
    int nb = n00b_pt_collect_nt_deep(tree, "binding", bind_nodes, 256);

    // Parse all bindings into an array.
    ffi_binding_t *parsed = n00b_alloc_array(ffi_binding_t, nb > 0 ? nb : 1);
    int            valid  = 0;

    for (int i = 0; i < nb; i++) {
        ffi_binding_t b = parse_binding(bind_nodes[i]);

        if (b.n00b_name && b.c_name) {
            parsed[valid++] = b;
        }
        else {
            fprintf(stderr, "ffi: skipping malformed binding\n");
        }
    }

    // Allocate the FFI module object.
    n00b_ffi_module_t *mod = n00b_alloc(n00b_ffi_module_t);
    mod->bindings      = parsed;
    mod->binding_count = (int32_t)valid;
    mod->session       = session;
    mod->installed     = false;

    // Pack the pointer into the opaque 16-byte result.
    n00b_embed_result_t result = {0};
    n00b_cg_val_t val = {
        .kind     = N00B_CG_VAL_IMM,
        .type_tag = N00B_CG_PTR,
        .aux      = (uint64_t)(uintptr_t)mod,
    };
    _Static_assert(sizeof(val) == sizeof(result),
                   "n00b_cg_val_t and n00b_embed_result_t must be same size");
    memcpy(&result, &val, sizeof(result));
    return result;
}

// ============================================================================
// install() — emit MIR wrappers for all bindings
// ============================================================================

void
n00b_ffi_module_install(n00b_ffi_module_t *self)
{
    if (!self || self->installed) {
        return;
    }

    n00b_cg_session_t *s = (n00b_cg_session_t *)self->session;

    if (!s) {
        fprintf(stderr, "ffi: install() called without a session\n");
        return;
    }

    ffi_binding_t *bindings = (ffi_binding_t *)self->bindings;

    bool ok = true;

    for (int32_t i = 0; i < self->binding_count; i++) {
        if (!generate_wrapper(s, &bindings[i])) {
            ok = false;
        }
    }

    self->installed = ok;
}

// ============================================================================
// Type registration — makes install() discoverable via method lookup
// ============================================================================

void
n00b_ffi_module_type_register(void)
{
    N00B_TYPE_REGISTER(n00b_ffi_module_t,
        N00B_TYPE_STATIC_TRANSIENT(r"ffi modules bind compiler and dynamic symbol state"),
        .literal_kind     = N00B_LIT_PREFIX,
        .literal_modifier = r"ffi",
    );

    n00b_type_add_method(typehash(n00b_ffi_module_t *), &(n00b_method_t){
        .fn   = (n00b_vtable_entry)n00b_ffi_module_install,
        .name = "install",
    });
}

// ============================================================================
// Registration
// ============================================================================

void
n00b_ffi_embed_register(n00b_dict_untyped_t *registry)
{
    n00b_embed_handler_t h = {
        .name       = n00b_string_from_cstr("ffi"),
        .bnf        = n00b_ffi_bnf(),
        .tokenizer  = ffi_tokenize,
        .handler    = ffi_handler,
        .user_data  = nullptr,
        .const_eval = true,
    };

    n00b_embed_register(registry, &h);
}

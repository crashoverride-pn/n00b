/**
 * @file n00b_demangle_rust.c
 * @brief Rust v0 symbol demangler (RFC 2603).
 *
 * Rewritten as a direct-output recursive descent parser (no tree nodes).
 * Uses malloc/realloc/free for internal temp buffers.  Exports C-string
 * entry points consumed by n00b_demangle.c.
 */

#include <ctype.h>
#include <stdbool.h>
#include <stdckdint.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"

// ============================================================================
// Backref list
// ============================================================================

typedef struct {
    const char **data;
    size_t       len;
    size_t       cap;
} backref_list_t;

static bool
backref_push(backref_list_t *bl, const char *pos)
{
    if (bl->len == bl->cap) {
        size_t new_cap = bl->cap ? bl->cap * 2 : 32;
        const char **p = n00b_alloc_array(const char *, new_cap);
        if (!p) return false;
        if (bl->data) {
            memcpy(p, bl->data, bl->len * sizeof(const char *));
            n00b_free(bl->data);
        }
        bl->data = p;
        bl->cap  = new_cap;
    }
    bl->data[bl->len++] = pos;
    return true;
}

// ============================================================================
// Parser state
// ============================================================================

typedef struct {
    const char    *input;
    const char    *pos;
    const char    *end;
    n00b_buffer_t *output;       // mutable accumulator (append=resize+memcpy,
    size_t         output_size;  // rewind=set output_size); byte_len synced at append
    bool           error;
    int            depth;
    int            max_depth;
    backref_list_t backrefs;
} rust_ctx_t;

static void
ctx_init(rust_ctx_t *ctx, const char *mangled)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->input      = mangled;
    ctx->pos        = mangled;
    ctx->end        = mangled + strlen(mangled);
    ctx->output     = n00b_buffer_new(256);
    ctx->max_depth  = 256;
}

static void
ctx_free(rust_ctx_t *ctx)
{
    // ctx->output is a GC-managed n00b_buffer; nothing to free explicitly.
    n00b_free(ctx->backrefs.data);
}

// ============================================================================
// Output helpers
// ============================================================================

static void
rappend_n(rust_ctx_t *ctx, const char *s, size_t n)
{
    // Grow the n00b_buffer to hold the new content (resize sets byte_len) and
    // copy in place.  byte_len stays == output_size after each append; rewinds
    // lower output_size only and are re-synced at the next append / at return.
    n00b_buffer_resize(ctx->output, ctx->output_size + n);
    memcpy((char *)ctx->output->data + ctx->output_size, s, n);
    ctx->output_size += n;
}

static void
rappend(rust_ctx_t *ctx, const char *s)
{
    if (s) rappend_n(ctx, s, strlen(s));
}

static void
rappend_char(rust_ctx_t *ctx, char c)
{
    rappend_n(ctx, &c, 1);
}

// ============================================================================
// Peek / match helpers
// ============================================================================

static inline bool rat_end(rust_ctx_t *ctx) { return ctx->pos >= ctx->end; }

static inline bool
rpeek(rust_ctx_t *ctx, char c)
{
    return !rat_end(ctx) && *ctx->pos == c;
}

static inline bool
rmatch(rust_ctx_t *ctx, char c)
{
    if (rpeek(ctx, c)) { ctx->pos++; return true; }
    return false;
}

static inline bool
rmatch_str(rust_ctx_t *ctx, const char *s)
{
    size_t len = strlen(s);
    if ((size_t)(ctx->end - ctx->pos) < len) return false;
    if (strncmp(ctx->pos, s, len) != 0) return false;
    ctx->pos += len;
    return true;
}

// ============================================================================
// Number parsing
// ============================================================================

static bool
rparse_decimal(rust_ctx_t *ctx, uint64_t *out)
{
    if (rat_end(ctx) || !isdigit(*ctx->pos)) return false;

    // RFC 2603: decimal-number = "0" | non-zero-digit {digit}
    // Leading zero means value is exactly 0; don't consume further digits.
    if (*ctx->pos == '0') {
        *out = 0;
        ctx->pos++;
        return true;
    }

    *out = 0;
    while (!rat_end(ctx) && isdigit(*ctx->pos)) {
        uint64_t next;
        if (ckd_mul(&next, *out, (uint64_t)10) || ckd_add(&next, next, (uint64_t)(*ctx->pos - '0'))) {
            ctx->error = true;
            return false;
        }
        *out = next;
        ctx->pos++;
    }
    return true;
}

// base-62-number → {digit | lower | upper} "_"
// The value is: if empty (just "_"), 0.  Otherwise the base-62 number + 1.
static bool
rparse_base62(rust_ctx_t *ctx, uint64_t *out)
{
    if (rmatch(ctx, '_')) { *out = 0; return true; }

    uint64_t val = 0;
    bool     found = false;
    while (!rat_end(ctx) && *ctx->pos != '_') {
        char c = *ctx->pos;
        int d;
        if (c >= '0' && c <= '9')      d = c - '0';
        else if (c >= 'a' && c <= 'z') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'Z') d = c - 'A' + 36;
        else return false;
        val = val * 62 + (uint64_t)d;
        found = true;
        ctx->pos++;
    }
    if (!rmatch(ctx, '_')) return false;
    *out = found ? val + 1 : 0;
    return true;
}

// ============================================================================
// Save / restore
// ============================================================================

typedef struct {
    const char *pos;
    size_t      output_size;
} rsave_t;

static void rsave(rust_ctx_t *ctx, rsave_t *s)   { s->pos = ctx->pos; s->output_size = ctx->output_size; }
static void rrestore(rust_ctx_t *ctx, rsave_t *s) { ctx->pos = s->pos; ctx->output_size = s->output_size; }

// ============================================================================
// Basic types
// ============================================================================

static const char *
rust_basic_type(char c)
{
    switch (c) {
    case 'a': return "i8";
    case 'b': return "bool";
    case 'c': return "char";
    case 'd': return "f64";
    case 'e': return "str";
    case 'f': return "f32";
    case 'h': return "u8";
    case 'i': return "isize";
    case 'j': return "usize";
    case 'l': return "i32";
    case 'm': return "u32";
    case 'n': return "i128";
    case 'o': return "u128";
    case 'p': return "_";
    case 's': return "i16";
    case 't': return "u16";
    case 'u': return "()";
    case 'v': return "...";
    case 'x': return "i64";
    case 'y': return "u64";
    case 'z': return "!";
    default:  return NULL;
    }
}

static const char *
rust_namespace_name(char c)
{
    if (c == 'C') return "{closure}";
    if (c == 'S') return "{shim}";
    return NULL;
}

// ============================================================================
// Forward declarations
// ============================================================================

static bool rust_path(rust_ctx_t *ctx);
static bool rust_type(rust_ctx_t *ctx);
static bool rust_const_val(rust_ctx_t *ctx);

// ============================================================================
// Identifier
// ============================================================================

// undisambiguated-identifier → "u"? decimal-number "_"? bytes
static bool
rust_undisambiguated_ident(rust_ctx_t *ctx)
{
    bool is_punycode = rmatch(ctx, 'u');

    uint64_t len;
    if (!rparse_decimal(ctx, &len)) return false;

    // Optional underscore separator (present when bytes start with digit or _)
    rmatch(ctx, '_');

    if ((size_t)(ctx->end - ctx->pos) < len) return false;

    if (!is_punycode) {
        rappend_n(ctx, ctx->pos, (size_t)len);
    } else {
        // Punycode (RFC 3492): mark it so it's visible in output.
        // Full Bootstring decoding is deferred.
        rappend(ctx, "{punycode:");
        rappend_n(ctx, ctx->pos, (size_t)len);
        rappend(ctx, "}");
    }
    ctx->pos += len;
    return true;
}

// identifier → disambiguator? undisambiguated-identifier
static bool
rust_identifier(rust_ctx_t *ctx)
{
    // Optional disambiguator: "s" base-62-number
    if (rmatch(ctx, 's')) {
        uint64_t disc;
        if (!rparse_base62(ctx, &disc)) return false;
        // Disambiguator not rendered.
    }
    return rust_undisambiguated_ident(ctx);
}

// impl-path → disambiguator? path
static bool
rust_impl_path(rust_ctx_t *ctx)
{
    if (rmatch(ctx, 's')) {
        uint64_t disc;
        if (!rparse_base62(ctx, &disc)) return false;
    }
    return rust_path(ctx);
}

// ============================================================================
// Lifetime
// ============================================================================

static bool
rust_lifetime(rust_ctx_t *ctx)
{
    if (!rmatch(ctx, 'L')) return false;

    uint64_t idx;
    if (!rparse_base62(ctx, &idx)) return false;

    if (idx == 0) {
        rappend(ctx, "'_");
    } else if (idx <= 26) {
        char buf[4];
        snprintf(buf, sizeof(buf), "'%c", (char)('a' + idx - 1));
        rappend(ctx, buf);
    } else {
        char buf[32];
        snprintf(buf, sizeof(buf), "'_%llu", (unsigned long long)idx);
        rappend(ctx, buf);
    }
    return true;
}

// ============================================================================
// Generic arg
// ============================================================================

// generic-arg → lifetime | type | "K" const
static bool
rust_generic_arg(rust_ctx_t *ctx)
{
    if (rpeek(ctx, 'L')) return rust_lifetime(ctx);
    if (rmatch(ctx, 'K')) return rust_const_val(ctx);
    return rust_type(ctx);
}

// ============================================================================
// Const
// ============================================================================

// const → type const-data | "p" | backref
static bool
rust_const_val(rust_ctx_t *ctx)
{
    if (rmatch(ctx, 'p')) {
        rappend(ctx, "_");
        return true;
    }

    // Backref — byte offset from symbol start (RFC 2603).
    if (rpeek(ctx, 'B')) {
        rmatch(ctx, 'B');
        uint64_t off;
        if (!rparse_base62(ctx, &off)) return false;

        if (off < (uint64_t)(ctx->end - ctx->input)) {
            const char *saved = ctx->pos;
            ctx->pos = ctx->input + off;
            bool ok = rust_const_val(ctx);
            ctx->pos = saved;
            return ok;
        }
        return false;
    }

    // type const-data: parse and discard the type, then parse hex const
    size_t out_start = ctx->output_size;
    if (!rust_type(ctx)) return false;

    // Discard the type output.
    ctx->output_size = out_start;

    bool negative = rmatch(ctx, 'n');

    uint64_t value = 0;
    bool has_digits = false;
    while (!rat_end(ctx) && *ctx->pos != '_') {
        char c = *ctx->pos;
        int d;
        if (c >= '0' && c <= '9')      d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else break;
        value = value * 16 + (uint64_t)d;
        has_digits = true;
        ctx->pos++;
    }
    if (!rmatch(ctx, '_')) return false;

    char buf[32];
    if (negative) snprintf(buf, sizeof(buf), "-%llu", (unsigned long long)value);
    else if (!has_digits) snprintf(buf, sizeof(buf), "0");
    else snprintf(buf, sizeof(buf), "%llu", (unsigned long long)value);
    rappend(ctx, buf);
    return true;
}

// ============================================================================
// Function signature
// ============================================================================

// fn-sig → binder? "U"? ("K" abi)? {type} "E" type
static bool
rust_fn_sig(rust_ctx_t *ctx)
{
    // Optional binder: "G" base-62-number
    if (rmatch(ctx, 'G')) {
        uint64_t bound;
        if (!rparse_base62(ctx, &bound)) return false;
        if (bound > 0) {
            rappend(ctx, "for<");
            for (uint64_t i = 0; i < bound; i++) {
                if (i > 0) rappend(ctx, ", ");
                char buf[16];
                snprintf(buf, sizeof(buf), "'%c", (char)('a' + i));
                rappend(ctx, buf);
            }
            rappend(ctx, "> ");
        }
    }

    if (rmatch(ctx, 'U')) rappend(ctx, "unsafe ");

    if (rmatch(ctx, 'K')) {
        rappend(ctx, "extern \"");
        if (rmatch(ctx, 'C')) {
            rappend(ctx, "C");
        } else {
            // Custom ABI
            rust_undisambiguated_ident(ctx);
        }
        rappend(ctx, "\" ");
    }

    rappend(ctx, "fn(");
    bool first = true;
    while (!rpeek(ctx, 'E') && !rat_end(ctx)) {
        if (!first) rappend(ctx, ", ");
        if (!rust_type(ctx)) return false;
        first = false;
    }
    if (!rmatch(ctx, 'E')) return false;
    rappend(ctx, ")");

    // Return type
    size_t ret_start = ctx->output_size;
    if (!rust_type(ctx)) return false;

    size_t ret_len = ctx->output_size - ret_start;
    bool is_unit = (ret_len == 2 &&
                    ((char *)ctx->output->data)[ret_start] == '(' &&
                    ((char *)ctx->output->data)[ret_start + 1] == ')');

    if (is_unit) {
        ctx->output_size = ret_start;
    } else {
        n00b_string_t *ret_text = n00b_string_from_raw(
            (char *)ctx->output->data + ret_start, (int64_t)ret_len);
        ctx->output_size = ret_start;
        rappend(ctx, " -> ");
        rappend(ctx, ret_text->data);
    }
    return true;
}

// ============================================================================
// Dyn bounds
// ============================================================================

// dyn-bounds → binder? {dyn-trait} "E"
static bool
rust_dyn_bounds(rust_ctx_t *ctx)
{
    if (rmatch(ctx, 'G')) {
        uint64_t bound;
        if (!rparse_base62(ctx, &bound)) return false;
        if (bound > 0) {
            rappend(ctx, "for<");
            for (uint64_t i = 0; i < bound; i++) {
                if (i > 0) rappend(ctx, ", ");
                char buf[16];
                snprintf(buf, sizeof(buf), "'%c", (char)('a' + i));
                rappend(ctx, buf);
            }
            rappend(ctx, "> ");
        }
    }

    bool first = true;
    while (!rpeek(ctx, 'E') && !rat_end(ctx)) {
        if (!first) rappend(ctx, " + ");

        // dyn-trait → path {dyn-trait-assoc-binding}
        if (!rust_path(ctx)) return false;
        first = false;

        // {dyn-trait-assoc-binding} → "p" undisambiguated-identifier type
        while (rpeek(ctx, 'p')) {
            rmatch(ctx, 'p');
            rappend(ctx, "<");
            rust_undisambiguated_ident(ctx);
            rappend(ctx, " = ");
            rust_type(ctx);
            rappend(ctx, ">");
        }
    }
    return rmatch(ctx, 'E');
}

// ============================================================================
// Path
// ============================================================================

static bool
rust_path(rust_ctx_t *ctx)
{
    if (rat_end(ctx) || ctx->error) return false;

    if (++ctx->depth > ctx->max_depth) {
        ctx->error = true;
        return false;
    }

    char tag = *ctx->pos;

    // crate-root → "C" identifier
    if (tag == 'C') {
        ctx->pos++;
        const char *br = ctx->pos;
        backref_push(&ctx->backrefs, br);
        bool ok = rust_identifier(ctx);
        ctx->depth--;
        return ok;
    }

    // inherent-impl → "M" impl-path type
    if (tag == 'M') {
        ctx->pos++;
        backref_push(&ctx->backrefs, ctx->pos);
        if (!rust_impl_path(ctx)) { ctx->depth--; return false; }
        rappend(ctx, "::<impl ");
        if (!rust_type(ctx)) { ctx->depth--; return false; }
        rappend(ctx, ">");
        ctx->depth--;
        return true;
    }

    // trait-impl → "X" impl-path type path
    if (tag == 'X') {
        ctx->pos++;
        backref_push(&ctx->backrefs, ctx->pos);
        if (!rust_impl_path(ctx)) { ctx->depth--; return false; }
        rappend(ctx, "::<impl ");
        if (!rust_type(ctx)) { ctx->depth--; return false; }
        rappend(ctx, " for ");
        if (!rust_path(ctx)) { ctx->depth--; return false; }
        rappend(ctx, ">");
        ctx->depth--;
        return true;
    }

    // trait-definition → "Y" type path
    if (tag == 'Y') {
        ctx->pos++;
        backref_push(&ctx->backrefs, ctx->pos);
        rappend(ctx, "<");
        if (!rust_type(ctx)) { ctx->depth--; return false; }
        rappend(ctx, " as ");
        if (!rust_path(ctx)) { ctx->depth--; return false; }
        rappend(ctx, ">");
        ctx->depth--;
        return true;
    }

    // nested-path → "N" namespace path identifier
    if (tag == 'N') {
        ctx->pos++;
        if (rat_end(ctx) || !isalpha(*ctx->pos)) { ctx->depth--; return false; }
        char ns = *ctx->pos;
        ctx->pos++;

        if (!rust_path(ctx)) { ctx->depth--; return false; }

        backref_push(&ctx->backrefs, ctx->pos);

        const char *ns_name = rust_namespace_name(ns);
        if (ns_name) {
            rappend(ctx, "::");
            rappend(ctx, ns_name);
        } else {
            rappend(ctx, "::");
        }
        bool ok = rust_identifier(ctx);
        ctx->depth--;
        return ok;
    }

    // generic-args → "I" path {generic-arg} "E"
    if (tag == 'I') {
        ctx->pos++;
        backref_push(&ctx->backrefs, ctx->pos);
        if (!rust_path(ctx)) { ctx->depth--; return false; }
        rappend(ctx, "<");
        bool first = true;
        while (!rpeek(ctx, 'E') && !rat_end(ctx)) {
            if (!first) rappend(ctx, ", ");
            if (!rust_generic_arg(ctx)) break;
            first = false;
        }
        rmatch(ctx, 'E');
        rappend(ctx, ">");
        ctx->depth--;
        return true;
    }

    // backref → "B" base-62-number  (byte offset from symbol start, RFC 2603)
    if (tag == 'B') {
        ctx->pos++;
        uint64_t off;
        if (!rparse_base62(ctx, &off)) { ctx->depth--; return false; }

        if (off < (uint64_t)(ctx->end - ctx->input)) {
            const char *saved = ctx->pos;
            ctx->pos = ctx->input + off;
            bool ok = rust_path(ctx);
            ctx->pos = saved;
            ctx->depth--;
            return ok;
        }
        ctx->depth--;
        return false;
    }

    ctx->depth--;
    return false;
}

// ============================================================================
// Type
// ============================================================================

static bool
rust_type(rust_ctx_t *ctx)
{
    if (rat_end(ctx) || ctx->error) return false;

    if (++ctx->depth > ctx->max_depth) {
        ctx->error = true;
        return false;
    }

    char c = *ctx->pos;

    // Basic type (single lowercase letter)
    const char *basic = rust_basic_type(c);
    if (basic) {
        ctx->pos++;
        rappend(ctx, basic);
        ctx->depth--;
        return true;
    }

    // Array: "A" type const
    if (c == 'A') {
        ctx->pos++;
        rappend(ctx, "[");
        if (!rust_type(ctx)) { ctx->depth--; return false; }
        rappend(ctx, "; ");
        if (!rust_const_val(ctx)) { ctx->depth--; return false; }
        rappend(ctx, "]");
        ctx->depth--;
        return true;
    }

    // Slice: "S" type
    if (c == 'S') {
        ctx->pos++;
        rappend(ctx, "[");
        if (!rust_type(ctx)) { ctx->depth--; return false; }
        rappend(ctx, "]");
        ctx->depth--;
        return true;
    }

    // Tuple: "T" {type} "E"
    if (c == 'T') {
        ctx->pos++;
        rappend(ctx, "(");
        bool first = true;
        while (!rpeek(ctx, 'E') && !rat_end(ctx)) {
            if (!first) rappend(ctx, ", ");
            if (!rust_type(ctx)) { ctx->depth--; return false; }
            first = false;
        }
        rmatch(ctx, 'E');
        rappend(ctx, ")");
        ctx->depth--;
        return true;
    }

    // Ref: "R" lifetime? type
    if (c == 'R') {
        ctx->pos++;
        rappend(ctx, "&");
        if (rpeek(ctx, 'L')) {
            rust_lifetime(ctx);
            rappend(ctx, " ");
        }
        bool ok = rust_type(ctx);
        ctx->depth--;
        return ok;
    }

    // Mut ref: "Q" lifetime? type
    if (c == 'Q') {
        ctx->pos++;
        rappend(ctx, "&mut ");
        if (rpeek(ctx, 'L')) {
            rust_lifetime(ctx);
            rappend(ctx, " ");
        }
        bool ok = rust_type(ctx);
        ctx->depth--;
        return ok;
    }

    // Const ptr: "P" type
    if (c == 'P') {
        ctx->pos++;
        rappend(ctx, "*const ");
        bool ok = rust_type(ctx);
        ctx->depth--;
        return ok;
    }

    // Mut ptr: "O" type
    if (c == 'O') {
        ctx->pos++;
        rappend(ctx, "*mut ");
        bool ok = rust_type(ctx);
        ctx->depth--;
        return ok;
    }

    // Fn: "F" fn-sig
    if (c == 'F') {
        ctx->pos++;
        bool ok = rust_fn_sig(ctx);
        ctx->depth--;
        return ok;
    }

    // Dyn: "D" dyn-bounds lifetime
    if (c == 'D') {
        ctx->pos++;
        rappend(ctx, "dyn ");
        if (!rust_dyn_bounds(ctx)) { ctx->depth--; return false; }
        if (rpeek(ctx, 'L')) {
            rappend(ctx, " + ");
            rust_lifetime(ctx);
        }
        ctx->depth--;
        return true;
    }

    // Backref: "B" base-62-number  (byte offset from symbol start, RFC 2603)
    if (c == 'B') {
        ctx->pos++;
        uint64_t off;
        if (!rparse_base62(ctx, &off)) { ctx->depth--; return false; }

        if (off < (uint64_t)(ctx->end - ctx->input)) {
            const char *saved = ctx->pos;
            ctx->pos = ctx->input + off;
            bool ok = rust_type(ctx);
            ctx->pos = saved;
            ctx->depth--;
            return ok;
        }
        ctx->depth--;
        return false;
    }

    // Named type (path)
    bool ok = rust_path(ctx);
    ctx->depth--;
    return ok;
}

// ============================================================================
// Top-level symbol-name
// ============================================================================

// symbol-name → "_R" decimal-number? path instantiating-crate? vendor-suffix?
static bool
rust_symbol_name(rust_ctx_t *ctx)
{
    if (!rmatch_str(ctx, "_R")) return false;

    // Optional version
    if (!rat_end(ctx) && isdigit(*ctx->pos) && *ctx->pos != '0') {
        uint64_t ver;
        rparse_decimal(ctx, &ver);
        if (ver != 0) return false;
    }

    if (!rust_path(ctx)) return false;

    // Optional instantiating crate — try to parse but discard output.
    size_t save_out = ctx->output_size;
    if (!rat_end(ctx)) {
        rsave_t s;
        rsave(ctx, &s);
        if (!rust_path(ctx)) {
            rrestore(ctx, &s);
        } else {
            // Discard the instantiating crate output.
            ctx->output_size = save_out;
        }
    }

    // Optional vendor suffix: ("." | "$") suffix — skip.
    if (!rat_end(ctx) && (*ctx->pos == '.' || *ctx->pos == '$'))
        ctx->pos = ctx->end;

    return true;
}

// ============================================================================
// Public C-string API (consumed by n00b_demangle.c)
// ============================================================================

char *
rust_demangle_cstr(const char *mangled)
{
    if (!mangled) return NULL;

    rust_ctx_t ctx;
    ctx_init(&ctx, mangled);

    bool ok = rust_symbol_name(&ctx);

    char *result = NULL;
    if (ok && !ctx.error && ctx.output_size > 0) {
        // Finalize: sync the buffer length to the logical size, then copy out a
        // standalone n00b-allocated C string (caller releases it with n00b_free).
        n00b_buffer_resize(ctx.output, ctx.output_size);
        result = n00b_alloc_array(char, ctx.output_size + 1);
        memcpy(result, ctx.output->data, ctx.output_size);
        result[ctx.output_size] = '\0';
    }

    ctx_free(&ctx);
    return result;
}

bool
rust_is_mangled_check(const char *name)
{
    if (!name) return false;
    if (name[0] == '_' && name[1] == 'R') {
        char c = name[2];
        return (c == 'C' || c == 'M' || c == 'X' || c == 'Y' ||
                c == 'N' || c == 'I' || c == 'B' ||
                (c >= '0' && c <= '9'));
    }
    return false;
}

/*
 * x509_der_tok.c — DER (X.690) → slay token-stream tokenizer (WP-042 Phase 1).
 *
 * See include/internal/crypto/x509_der_tok.h. n00b primitives only: the source
 * is an n00b_buffer_t walked by byte offset (n00b_buffer_get_index); content +
 * full-element slices are n00b_buffer_get_slice copies. One recursive walker
 * runs in COUNT mode (validate + size) then FILL mode (emit tokens).
 */

#include "n00b.h"

#include "core/buffer.h"
#include "core/string.h"
#include "slay/grammar.h"
#include "slay/token.h"
#include "internal/crypto/x509_der_tok.h"

#define N00B_DER_MAX_DEPTH 64

typedef struct {
    n00b_grammar_t     *g;
    n00b_buffer_t      *der;
    int64_t             end;   /* n00b_buffer_len(der) */
    n00b_token_info_t **arr;   /* nullptr in COUNT mode */
    int32_t             count;
    n00b_string_t      *error; /* set on first failure */
} der_ctx_t;

/* Byte read; callers bounds-check (i < ctx->end) first. */
static uint8_t
bget(der_ctx_t *ctx, int64_t i)
{
    n00b_result_t(uint8_t) r = n00b_buffer_get_index(ctx->der, i);
    return n00b_result_is_ok(r) ? n00b_result_get(r) : 0;
}

/* ---- tag → grammar terminal name (matches grammars/x509_der.bnf) ---- */

static const char *
der_open_name(uint8_t cls, uint32_t tag)
{
    if (cls == 0) {
        switch (tag) {
        case 0x10: return "SEQ_OPEN";
        case 0x11: return "SET_OPEN";
        default:   return "UNKNOWN_OPEN";
        }
    }
    if (cls == 2) {
        switch (tag) {
        case 0: return "CTX0_OPEN";
        case 1: return "CTX1_OPEN";
        case 2: return "CTX2_OPEN";
        case 3: return "CTX3_OPEN";
        default: return "CTX_OPEN_OTHER";
        }
    }
    return "UNKNOWN_OPEN";
}

static const char *
der_prim_name(uint8_t cls, uint32_t tag)
{
    if (cls == 0) {
        switch (tag) {
        case 0x01: return "BOOLEAN";
        case 0x02: return "INTEGER";
        case 0x03: return "BIT_STRING";
        case 0x04: return "OCTET_STRING";
        case 0x05: return "NULL";
        case 0x06: return "OID";
        case 0x0A: return "ENUMERATED";
        case 0x0C: return "UTF8_STRING";
        case 0x13: return "PRINTABLE_STRING";
        case 0x14: return "T61_STRING";
        case 0x16: return "IA5_STRING";
        case 0x17: return "UTC_TIME";
        case 0x18: return "GEN_TIME";
        case 0x1C: return "UNIVERSAL_STRING";
        case 0x1E: return "BMP_STRING";
        default:   return "UNKNOWN_PRIM";
        }
    }
    if (cls == 2) {
        return "CTX_PRIM";
    }
    return "UNKNOWN_PRIM";
}

/* ---- DER tag / length readers (definite-length, minimal-form only) ---- */

static bool
der_read_tag(der_ctx_t *ctx, int64_t *pos, uint8_t *cls, bool *constructed,
             uint32_t *tagnum)
{
    if (*pos >= ctx->end) {
        ctx->error = n00b_string_from_cstr("DER: truncated tag");
        return false;
    }
    uint8_t b      = bget(ctx, (*pos)++);
    *cls           = (uint8_t)((b >> 6) & 0x3);
    *constructed   = (bool)((b >> 5) & 0x1);
    uint32_t low   = (uint32_t)(b & 0x1f);

    if (low != 0x1f) {
        *tagnum = low;
        return true;
    }
    uint32_t v   = 0;
    int      cnt = 0;
    for (;;) {
        if (*pos >= ctx->end) {
            ctx->error = n00b_string_from_cstr("DER: truncated high-tag-number");
            return false;
        }
        uint8_t c = bget(ctx, (*pos)++);
        if (cnt == 0 && c == 0x80) {
            ctx->error = n00b_string_from_cstr("DER: non-minimal high-tag-number");
            return false;
        }
        if (++cnt > 4) {
            ctx->error = n00b_string_from_cstr("DER: high-tag-number too large");
            return false;
        }
        v = (v << 7) | (uint32_t)(c & 0x7f);
        if (!(c & 0x80)) {
            *tagnum = v;
            return true;
        }
    }
}

static bool
der_read_len(der_ctx_t *ctx, int64_t *pos, int64_t *outlen)
{
    if (*pos >= ctx->end) {
        ctx->error = n00b_string_from_cstr("DER: truncated length");
        return false;
    }
    uint8_t b = bget(ctx, (*pos)++);
    if (b < 0x80) {
        *outlen = (int64_t)b;
        return true;
    }
    if (b == 0x80) {
        ctx->error = n00b_string_from_cstr("DER: indefinite length forbidden");
        return false;
    }
    if (b == 0xff) {
        ctx->error = n00b_string_from_cstr("DER: reserved length 0xff");
        return false;
    }
    int n = (int)(b & 0x7f);
    if (n > 8) {
        ctx->error = n00b_string_from_cstr("DER: length field too large");
        return false;
    }
    if (*pos + n > ctx->end) {
        ctx->error = n00b_string_from_cstr("DER: truncated long-form length");
        return false;
    }
    if (bget(ctx, *pos) == 0x00) {
        ctx->error = n00b_string_from_cstr("DER: non-minimal length (leading zero)");
        return false;
    }
    int64_t L = 0;
    for (int i = 0; i < n; i++) {
        L = (L << 8) | (int64_t)bget(ctx, *pos + i);
    }
    *pos += n;
    if (L < 0x80) {
        ctx->error = n00b_string_from_cstr("DER: non-minimal length (long form for small value)");
        return false;
    }
    *outlen = L;
    return true;
}

/* Emit a token. content_start<0 => no content; elem_start<0 => no elem.
 * Slices are taken only in FILL mode. */
static void
der_emit(der_ctx_t *ctx, const char *name, int64_t content_start,
         int64_t content_end, int64_t elem_start, int64_t elem_end,
         uint8_t cls, bool constructed, uint32_t tagnum)
{
    int32_t idx = ctx->count++;
    if (ctx->arr == nullptr) {
        return; /* COUNT mode */
    }
    n00b_token_info_t *t = n00b_alloc(n00b_token_info_t);
    /* g may be nullptr in decode mode (callers re-tokenize an extnValue just to
     * read der_value, not to parse) — leave tid=0 then. */
    t->tid    = (ctx->g != nullptr)
                    ? n00b_register_literal_type(ctx->g, n00b_string_from_cstr(name))
                    : 0;
    t->index  = idx;
    t->line   = 1;
    t->column = (uint32_t)(idx + 1);

    n00b_der_value_t *v = n00b_alloc(n00b_der_value_t);
    v->content     = (content_start >= 0)
                         ? n00b_buffer_get_slice(ctx->der, content_start, content_end)
                         : nullptr;
    v->elem        = (elem_start >= 0)
                         ? n00b_buffer_get_slice(ctx->der, elem_start, elem_end)
                         : nullptr;
    v->tag_class   = cls;
    v->constructed = constructed;
    v->tag_number  = tagnum;
    t->user_info   = v;

    ctx->arr[idx] = t;
}

static bool
der_walk(der_ctx_t *ctx, int64_t *pos, int64_t end, int depth)
{
    if (depth > N00B_DER_MAX_DEPTH) {
        ctx->error = n00b_string_from_cstr("DER: nesting too deep");
        return false;
    }
    int64_t  tagstart = *pos;
    uint8_t  cls;
    bool     constructed;
    uint32_t tagnum;
    if (!der_read_tag(ctx, pos, &cls, &constructed, &tagnum)) {
        return false;
    }
    int64_t len;
    if (!der_read_len(ctx, pos, &len)) {
        return false;
    }
    if (len > end - *pos) {
        ctx->error = n00b_string_from_cstr("DER: value length exceeds buffer");
        return false;
    }
    int64_t vstart = *pos;

    if (constructed) {
        int64_t vend = vstart + len;
        der_emit(ctx, der_open_name(cls, tagnum), -1, 0, tagstart, vend,
                 cls, true, tagnum);
        int64_t cur = vstart;
        while (cur < vend) {
            if (!der_walk(ctx, &cur, vend, depth + 1)) {
                return false;
            }
        }
        if (cur != vend) {
            ctx->error = n00b_string_from_cstr("DER: constructed content length mismatch");
            return false;
        }
        der_emit(ctx, "CLOSE", -1, 0, -1, 0, cls, true, tagnum);
        *pos = vend;
    }
    else {
        der_emit(ctx, der_prim_name(cls, tagnum), vstart, vstart + len,
                 tagstart, vstart + len, cls, false, tagnum);
        *pos = vstart + len;
    }
    return true;
}

n00b_der_tok_result_t
n00b_x509_der_tokenize(n00b_buffer_t *der, n00b_grammar_t *g)
{
    n00b_der_tok_result_t r = {};

    if (der == nullptr || n00b_buffer_len(der) == 0) {
        r.error = n00b_string_from_cstr("DER: empty input");
        return r;
    }
    int64_t end = (int64_t)n00b_buffer_len(der);

    /* Pass 1 — validate + count. */
    der_ctx_t ctx = {.g = g, .der = der, .end = end, .arr = nullptr, .count = 0};
    int64_t   p   = 0;
    if (!der_walk(&ctx, &p, end, 0)) {
        r.error = ctx.error;
        return r;
    }
    if (p != end) {
        r.error = n00b_string_from_cstr("DER: trailing bytes after top-level element");
        return r;
    }

    int32_t n = ctx.count;
    if (n <= 0) {
        r.error = n00b_string_from_cstr("DER: no tokens produced");
        return r;
    }

    /* Pass 2 — emit tokens into the exact-size array. */
    n00b_token_info_t **arr = n00b_alloc_array(n00b_token_info_t *, n);
    der_ctx_t fill = {.g = g, .der = der, .end = end, .arr = arr, .count = 0};
    p = 0;
    if (!der_walk(&fill, &p, end, 0)) {
        r.error = fill.error;
        return r;
    }

    r.tokens = arr;
    r.count  = fill.count;
    return r;
}

/*
 * x509_der_tok.c — DER (X.690) → slay token-stream tokenizer (WP-042 Phase 1).
 *
 * See include/internal/crypto/x509_der_tok.h. Default-deny X.690 DER framing:
 * one recursive walker runs in COUNT mode (validate + size) then FILL mode
 * (emit tokens), so the traversal + validation logic lives in exactly one place.
 */

#include "n00b.h"

#include "core/alloc.h"
#include "core/string.h"
#include "slay/grammar.h"
#include "slay/token.h"
#include "internal/crypto/x509_der_tok.h"

#define N00B_DER_MAX_DEPTH 64

typedef struct {
    n00b_grammar_t     *g;
    n00b_token_info_t **arr;   /* NULL in COUNT mode */
    int32_t             count; /* tokens emitted / counted so far */
    n00b_string_t      *error; /* set on first failure */
} der_ctx_t;

/* ---- tag → grammar terminal name (matches grammars/x509_der.bnf) ---- */

static const char *
der_open_name(uint8_t cls, uint32_t tag)
{
    if (cls == 0) { /* universal constructed */
        switch (tag) {
        case 0x10: return "SEQ_OPEN"; /* SEQUENCE */
        case 0x11: return "SET_OPEN"; /* SET */
        default:   return "UNKNOWN_OPEN";
        }
    }
    if (cls == 2) { /* context-tagged constructed [n] */
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
    if (cls == 0) { /* universal primitive */
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
        return "CTX_PRIM"; /* IMPLICIT context-tagged primitive */
    }
    return "UNKNOWN_PRIM";
}

/* ---- DER tag / length readers (definite-length, minimal-form only) ---- */

static bool
der_read_tag(const uint8_t **pp, const uint8_t *end, uint8_t *cls,
             bool *constructed, uint32_t *tagnum, der_ctx_t *ctx)
{
    if (*pp >= end) {
        ctx->error = n00b_string_from_cstr("DER: truncated tag");
        return false;
    }
    uint8_t b      = *(*pp)++;
    *cls           = (uint8_t)((b >> 6) & 0x3);
    *constructed   = (bool)((b >> 5) & 0x1);
    uint32_t low   = (uint32_t)(b & 0x1f);

    if (low != 0x1f) {
        *tagnum = low;
        return true;
    }
    /* high-tag-number form: base-128, minimal (no leading 0x80). */
    uint32_t v   = 0;
    int      cnt = 0;
    for (;;) {
        if (*pp >= end) {
            ctx->error = n00b_string_from_cstr("DER: truncated high-tag-number");
            return false;
        }
        uint8_t c = *(*pp)++;
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
der_read_len(const uint8_t **pp, const uint8_t *end, size_t *outlen,
             der_ctx_t *ctx)
{
    if (*pp >= end) {
        ctx->error = n00b_string_from_cstr("DER: truncated length");
        return false;
    }
    uint8_t b = *(*pp)++;
    if (b < 0x80) { /* short form */
        *outlen = (size_t)b;
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
    int n = (int)(b & 0x7f); /* number of subsequent length octets */
    if (n > 8) {
        ctx->error = n00b_string_from_cstr("DER: length field too large");
        return false;
    }
    if (*pp + n > end) {
        ctx->error = n00b_string_from_cstr("DER: truncated long-form length");
        return false;
    }
    if ((*pp)[0] == 0x00) {
        ctx->error = n00b_string_from_cstr("DER: non-minimal length (leading zero)");
        return false;
    }
    size_t L = 0;
    for (int i = 0; i < n; i++) {
        L = (L << 8) | (size_t)(*pp)[i];
    }
    *pp += n;
    if (L < 0x80) {
        ctx->error = n00b_string_from_cstr("DER: non-minimal length (long form for small value)");
        return false;
    }
    *outlen = L;
    return true;
}

/* ---- token emit (no-op in COUNT mode) ---- */

static void
der_emit(der_ctx_t *ctx, const char *name, const uint8_t *content,
         size_t content_len, const uint8_t *elem, size_t elem_len,
         uint8_t cls, bool constructed, uint32_t tagnum)
{
    int32_t idx = ctx->count++;
    if (ctx->arr == NULL) {
        return; /* COUNT mode */
    }
    n00b_token_info_t *t = n00b_alloc(n00b_token_info_t);
    t->tid    = n00b_register_literal_type(ctx->g, n00b_string_from_cstr(name));
    t->index  = idx;
    t->line   = 1;
    t->column = (uint32_t)(idx + 1);

    n00b_der_value_t *v = n00b_alloc(n00b_der_value_t);
    v->content     = content;
    v->content_len = content_len;
    v->elem        = elem;
    v->elem_len    = elem_len;
    v->tag_class   = cls;
    v->constructed = constructed;
    v->tag_number  = tagnum;
    t->user_info   = v;

    ctx->arr[idx] = t;
}

/* Parse one TLV at *pp (within [.., end)); recurse into constructed values. */
static bool
der_walk(der_ctx_t *ctx, const uint8_t **pp, const uint8_t *end, int depth)
{
    if (depth > N00B_DER_MAX_DEPTH) {
        ctx->error = n00b_string_from_cstr("DER: nesting too deep");
        return false;
    }
    const uint8_t *tagstart = *pp; /* start of this element's full TLV */
    uint8_t  cls;
    bool     constructed;
    uint32_t tagnum;
    if (!der_read_tag(pp, end, &cls, &constructed, &tagnum, ctx)) {
        return false;
    }
    size_t len;
    if (!der_read_len(pp, end, &len, ctx)) {
        return false;
    }
    if (len > (size_t)(end - *pp)) {
        ctx->error = n00b_string_from_cstr("DER: value length exceeds buffer");
        return false;
    }
    const uint8_t *vstart = *pp;

    if (constructed) {
        const uint8_t *vend     = vstart + len;
        size_t         elem_len = (size_t)(vend - tagstart);
        der_emit(ctx, der_open_name(cls, tagnum), NULL, 0, tagstart, elem_len,
                 cls, true, tagnum);
        const uint8_t *cur = vstart;
        while (cur < vend) {
            if (!der_walk(ctx, &cur, vend, depth + 1)) {
                return false;
            }
        }
        if (cur != vend) {
            ctx->error = n00b_string_from_cstr("DER: constructed content length mismatch");
            return false;
        }
        der_emit(ctx, "CLOSE", NULL, 0, NULL, 0, cls, true, tagnum);
        *pp = vend;
    }
    else {
        size_t elem_len = (size_t)(vstart + len - tagstart);
        der_emit(ctx, der_prim_name(cls, tagnum), vstart, len, tagstart,
                 elem_len, cls, false, tagnum);
        *pp = vstart + len;
    }
    return true;
}

n00b_der_tok_result_t
n00b_x509_der_tokenize(const uint8_t *der, size_t len, n00b_grammar_t *g)
{
    n00b_der_tok_result_t r = {0};

    if (der == NULL || len == 0 || g == NULL) {
        r.error = n00b_string_from_cstr("DER: empty input or null grammar");
        return r;
    }

    /* Pass 1 — validate + count (no allocation of tokens). */
    der_ctx_t ctx     = {.g = g, .arr = NULL, .count = 0, .error = NULL};
    const uint8_t *p  = der;
    const uint8_t *e  = der + len;
    if (!der_walk(&ctx, &p, e, 0)) {
        r.error = ctx.error;
        return r;
    }
    if (p != e) {
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
    der_ctx_t fill = {.g = g, .arr = arr, .count = 0, .error = NULL};
    p = der;
    e = der + len;
    if (!der_walk(&fill, &p, e, 0)) {
        r.error = fill.error; /* should not happen (pass 1 validated) */
        return r;
    }

    r.tokens = arr;
    r.count  = fill.count;
    r.error  = NULL;
    return r;
}

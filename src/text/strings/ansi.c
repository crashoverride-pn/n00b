#include "text/strings/ansi.h"
#include "text/unicode/encoding.h"
#include "text/unicode/properties.h"
#include "text/strings/string_convert.h"
#include "text/strings/string_ops.h"
#include "internal/text/unicode/raw.h"
#include "core/alloc.h"
#include "core/string.h"
#include <string.h>

// -------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------

static inline n00b_ansi_node_t *
ansi_node(n00b_ansi_ctx *ctx, n00b_ansi_kind kind, int backup)
{
    n00b_ansi_node_t *result = n00b_alloc(n00b_ansi_node_t);
    result->kind             = kind;
    result->start            = ctx->cur - (backup ? 1 : 0);

    n00b_list_push(ctx->results, result);

    return result;
}

static inline char *
ansi_advance(n00b_ansi_ctx *ctx, int l)
{
    ctx->cur += l;
    return ctx->cur;
}

static inline int
ansi_current(n00b_ansi_ctx *ctx, n00b_codepoint_t *ptr)
{
    if (ctx->cur == ctx->end) {
        *ptr = 0;
        return 0;
    }

    uint32_t avail = (uint32_t)(ctx->end - ctx->cur);
    if (avail > 4) {
        avail = 4;
    }

    uint32_t pos = 0;
    int32_t  cp  = n00b_unicode_utf8_decode(ctx->cur, avail, &pos);

    if (cp < 0) {
        *ptr = 0;
        return -1;
    }

    *ptr = (n00b_codepoint_t)cp;
    return (int)pos;
}

static inline bool
is_control_category(n00b_codepoint_t cp)
{
    n00b_unicode_gc_t cat = n00b_unicode_general_category(cp);
    return cat == N00B_UNICODE_GC_CC;
}

static inline void
c0_code(n00b_ansi_ctx *ctx, int l)
{
    n00b_ansi_node_t *n = ansi_node(ctx, N00B_ANSI_C0_CODE, 0);
    n->ctrl.ctrl_byte   = *ctx->cur;
    n->end              = ansi_advance(ctx, l);
}

static inline void
c1_code(n00b_ansi_ctx *ctx, int l)
{
    n00b_ansi_node_t *n = ansi_node(ctx, N00B_ANSI_C1_CODE, 0);
    n00b_codepoint_t  cp;
    ansi_current(ctx, &cp);
    n->ctrl.ctrl_byte = cp;
    n->end            = ansi_advance(ctx, l);
}

static inline void
printable_string(n00b_ansi_ctx *ctx, int l)
{
    n00b_ansi_node_t *n = ansi_node(ctx, N00B_ANSI_TEXT, 0);
    n00b_codepoint_t  cp;

    while (ctx->cur < ctx->end) {
        ansi_advance(ctx, l);
        l = ansi_current(ctx, &cp);
        if (l < 0) {
            n->kind = N00B_ANSI_PARTIAL;
            return;
        }

        if (is_control_category(cp)) {
            break;
        }
    }

    n->end = ctx->cur;
}

static inline void
node_invalidate(n00b_ansi_ctx *ctx, n00b_ansi_node_t *n)
{
    n->kind = N00B_ANSI_INVALID;
    n->end  = ctx->cur;
}

static inline void
private_ctrl(n00b_ansi_ctx *ctx, n00b_codepoint_t cp, int l, int backup)
{
    n00b_ansi_node_t *n   = ansi_node(ctx, N00B_ANSI_PRIVATE_CONTROL, backup);
    int               len = 0;

    n->ctrl.ppi    = (uint8_t)cp;
    n->ctrl.pstart = ansi_advance(ctx, l);

    while (ctx->cur < ctx->end) {
        l = ansi_current(ctx, &cp);
        if (l < 0) {
            n->kind = N00B_ANSI_PARTIAL;
            return;
        }
        if (cp < 0x30 || cp > 0x3f) {
            break;
        }
        len++;
        ansi_advance(ctx, l);
    }

    n->ctrl.plen   = len;
    n->ctrl.istart = ctx->cur;
    len            = 0;

    while (ctx->cur < ctx->end) {
        if (cp < 0x20 || cp > 0x2f) {
            break;
        }
        len++;

        l = ansi_current(ctx, &cp);
        if (l < 0) {
            n->kind = N00B_ANSI_PARTIAL;
            return;
        }
        ansi_advance(ctx, l);
    }

    n->ctrl.ilen = len;

    if (ctx->cur == ctx->end && !cp) {
        n->kind = N00B_ANSI_PARTIAL;
        return;
    }

    if (cp < 0x40 || cp > 0x73) {
        node_invalidate(ctx, n);
    }
    else {
        n->ctrl.ctrl_byte = (uint8_t)cp;
    }

    n->end = ansi_advance(ctx, l);
}

static inline void
normal_ctrl(n00b_ansi_ctx *ctx, n00b_codepoint_t cp, int l, int bu)
{
    n00b_ansi_node_t *n        = ansi_node(ctx, N00B_ANSI_CONTROL_SEQUENCE, bu);
    bool              colon_ok = true;
    int               len      = 0;

    l              = ansi_current(ctx, &cp);
    n->ctrl.pstart = ctx->cur;

    if (l < 0) {
        n->kind = N00B_ANSI_PARTIAL;
        return;
    }

    while (ctx->cur < ctx->end) {
        if (cp >= '0' && cp <= '9') {
param_advance:
            ansi_advance(ctx, l);
            l = ansi_current(ctx, &cp);
            if (l < 0) {
                n->kind = N00B_ANSI_PARTIAL;
                return;
            }
            n->ctrl.plen++;
            len++;
            continue;
        }
        if (cp == ';') {
            colon_ok = true;
            goto param_advance;
        }
        if (cp == ':') {
            if (!colon_ok) {
                break;
            }
            colon_ok = false;
            goto param_advance;
        }
        break;
    }

    n->ctrl.plen   = len;
    n->ctrl.istart = ctx->cur;
    len            = 0;

    while (ctx->cur < ctx->end) {
        if (cp < 0x20 || cp > 0x2f) {
            break;
        }
        len++;

        l = ansi_current(ctx, &cp);
        ansi_advance(ctx, l);
    }

    n->ctrl.ilen = len;

    if (ctx->cur == ctx->end && !cp) {
        n->kind = N00B_ANSI_PARTIAL;
        return;
    }

    if (cp < 0x40 || cp > 0x73) {
        node_invalidate(ctx, n);
    }
    else {
        n->ctrl.ctrl_byte = (uint8_t)cp;
    }

    n->end = ansi_advance(ctx, l);
}

static inline void
control_sequence(n00b_ansi_ctx *ctx, int backup)
{
    n00b_codepoint_t cp;
    int              l = ansi_current(ctx, &cp);

    if (l <= 0) {
        ansi_node(ctx, N00B_ANSI_PARTIAL, backup);
        return;
    }
    if (cp >= 0x3c && cp <= 0x3f) {
        private_ctrl(ctx, cp, l, backup);
    }
    else {
        normal_ctrl(ctx, cp, l, backup);
    }
}

static inline void
nf_sequence(n00b_ansi_ctx *ctx, n00b_codepoint_t cp, int l)
{
    n00b_ansi_node_t *n = ansi_node(ctx, N00B_ANSI_NF_SEQUENCE, true);

    do {
        n->end = ansi_advance(ctx, l);
        l      = ansi_current(ctx, &cp);
        if (l < 0) {
            n->kind = N00B_ANSI_PARTIAL;
            return;
        }
    } while (ctx->cur < ctx->end && cp >= 0x20 && cp < 0x2f);

    if (ctx->cur == ctx->end && cp == 0) {
        n->kind = N00B_ANSI_PARTIAL;
        return;
    }

    if (cp < 0x30 || cp > 0x7e) {
        node_invalidate(ctx, n);
    }
    else {
        n->end = ansi_advance(ctx, l);
    }
}

static inline void
fp_sequence(n00b_ansi_ctx *ctx, n00b_codepoint_t cp, int l)
{
    n00b_ansi_node_t *n = ansi_node(ctx, N00B_ANSI_FP_SEQUENCE, true);
    n->end              = ansi_advance(ctx, l);
}

static inline void
fe_sequence(n00b_ansi_ctx *ctx, n00b_codepoint_t cp, int l)
{
    n00b_ansi_node_t *n = ansi_node(ctx, N00B_ANSI_FE_SEQUENCE, true);
    n->end              = ansi_advance(ctx, l);
}

static inline void
fs_sequence(n00b_ansi_ctx *ctx, n00b_codepoint_t cp, int l)
{
    n00b_ansi_node_t *n = ansi_node(ctx, N00B_ANSI_FS_SEQUENCE, true);
    n->end              = ansi_advance(ctx, l);
}

static inline void
bad_sequence(n00b_ansi_ctx *ctx, n00b_codepoint_t cp, int l)
{
    n00b_ansi_node_t *n = ansi_node(ctx, N00B_ANSI_INVALID, true);
    n->end              = ansi_advance(ctx, l);
}

static inline void
command_string(n00b_ansi_ctx *ctx, n00b_codepoint_t cp, int l, int backup)
{
    n00b_ansi_node_t *n       = ansi_node(ctx, N00B_ANSI_CRL_STR_CMD, backup);
    bool              got_esc = false;
    bool              got_eos = false;

    while (ctx->cur < ctx->end) {
        l = ansi_current(ctx, &cp);
        if (cp == 0x9c || (got_esc && cp == 0x5c)) {
            got_eos = true;
            ansi_advance(ctx, l);
            break;
        }
        if (cp == 0x1b) {
            got_esc = true;
            goto advance;
        }
        got_esc = false;
        if (cp >= 0x08 && cp <= 0xd) {
            goto advance;
        }
        if (cp >= 0x20 && cp <= 0x7e) {
            goto advance;
        }
        if (cp >= 0xa0) {
advance:
            ansi_advance(ctx, l);
            l = ansi_current(ctx, &cp);
            continue;
        }

        node_invalidate(ctx, n);
        return;
    }

    n->end = ctx->cur;

    if (!got_eos) {
        n->kind = N00B_ANSI_PARTIAL;
    }
}

static inline void
character_string(n00b_ansi_ctx *ctx, int backup)
{
    n00b_ansi_node_t *n = ansi_node(ctx, N00B_ANSI_CTL_STR_CHAR, backup);
    n00b_codepoint_t  cp;
    int               l;
    bool              got_esc = false;
    bool              got_eos = false;

    while (ctx->cur < ctx->end) {
        l = ansi_current(ctx, &cp);
        if (cp == 0x9c || (got_esc && cp == 0x5c)) {
            got_eos = true;
            ansi_advance(ctx, l);
            break;
        }
        if (cp == 0x1b) {
            got_esc = true;
            goto advance;
        }
        got_esc = false;
        if (cp == 0x18 || cp == 0x1a || (cp > 0x7f && cp < 0xa0)) {
            node_invalidate(ctx, n);
            return;
        }
advance:
        ansi_advance(ctx, l);
        l = ansi_current(ctx, &cp);
        continue;
    }

    n->end = ctx->cur;

    if (!got_eos) {
        n->kind = N00B_ANSI_PARTIAL;
    }
}

static inline void
control_start(n00b_ansi_ctx *ctx, n00b_codepoint_t cp, int l)
{
    if (cp == 0x9b) {
        ansi_advance(ctx, l);
        control_sequence(ctx, 0);
        return;
    }

    if (cp == 0x98) {
        ansi_advance(ctx, l);
        character_string(ctx, 0);
        return;
    }

    if (cp == 0x90 || (cp >= 0x9d && cp <= 0x9f)) {
        command_string(ctx, cp, l, 0);
        return;
    }

    if (cp == 0x1b) { // ESC
        ansi_advance(ctx, l);
        if (ctx->end == ctx->cur) {
            ansi_node(ctx, N00B_ANSI_PARTIAL, 1);
            return;
        }
        l = ansi_current(ctx, &cp);
        switch (cp) {
        case 0x5b:
            ansi_advance(ctx, l);
            control_sequence(ctx, 1);
            return;
        case 0x50:
        case 0x5d:
        case 0x5e:
        case 0x5f:
            command_string(ctx, cp, l, 1);
            return;
        case 0x58:
            ansi_advance(ctx, l);
            character_string(ctx, 1);
            return;
        default:
            if (cp >= 0x20 && cp <= 0x2f) {
                nf_sequence(ctx, cp, l);
                return;
            }
            if (cp >= 0x30 && cp <= 0x3f) {
                fp_sequence(ctx, cp, l);
                return;
            }
            if (cp >= 0x40 && cp <= 0x5a && cp != 0x50 && cp != 0x58) {
                fe_sequence(ctx, cp, l);
                return;
            }
            if (cp >= 0x60 && cp <= 0x7e) {
                fs_sequence(ctx, cp, l);
                return;
            }
            bad_sequence(ctx, cp, l);
            return;
        }
    }

    if (cp < 0x1f) {
        c0_code(ctx, l);
    }
    else {
        c1_code(ctx, l);
    }
}

// -------------------------------------------------------------------
// Internal parse loop
// -------------------------------------------------------------------

static void
n00b_ansi_parse_internal(n00b_ansi_ctx *ctx)
{
    n00b_codepoint_t cp;

    while (ctx->cur < ctx->end) {
        int l = ansi_current(ctx, &cp);
        if (l < 0) {
            return;
        }

        if (is_control_category(cp)) {
            control_start(ctx, cp, l);
        }
        else {
            printable_string(ctx, l);
        }
    }
}

// -------------------------------------------------------------------
// Combine partial from previous buffer with new buffer
// -------------------------------------------------------------------

static inline n00b_buffer_t *
combine_partial(n00b_ansi_ctx *ctx, n00b_buffer_t *b)
{
    n00b_ansi_node_t *n = n00b_option_get(n00b_list_pop(n00b_ansi_node_t *, ctx->results));

    char *lower = ctx->buf_start;
    while (n->start > lower && *n->start != '\x1b') {
        --n->start;
    }

    int diff = (int)(ctx->end - n->start);

    if (((int64_t)b->alloc_len) - ((int64_t)b->byte_len) > diff) {
        memmove(b->data + diff, b->data, b->byte_len);
        memcpy(b->data, n->start, diff);
        b->byte_len += diff;
        return b;
    }

    int             new_len = (int)b->byte_len + diff;
    n00b_buffer_t  *new_buf = n00b_buffer_from_bytes(nullptr, new_len);
    memcpy(new_buf->data, n->start, diff);
    memcpy(new_buf->data + diff, b->data, b->byte_len);
    new_buf->byte_len = new_len;

    return new_buf;
}

// -------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------

n00b_ansi_ctx *
n00b_ansi_parser_create() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;

    n00b_ansi_ctx *result = n00b_alloc_with_opts(n00b_ansi_ctx, &(n00b_alloc_opts_t){.allocator = allocator});
    result->results       = n00b_list_new(n00b_ansi_node_t *, .allocator = allocator);

    return result;
}

void
n00b_ansi_parse(n00b_ansi_ctx *ctx, n00b_buffer_t *b)
{
    size_t len = n00b_list_len(ctx->results);

    if (len) {
        n00b_ansi_node_t *n = n00b_list_get(ctx->results, len - 1);

        if (n->kind == N00B_ANSI_PARTIAL) {
            b = combine_partial(ctx, b);
        }
    }

    ctx->buf_start = b->data;
    ctx->cur       = b->data;
    ctx->end       = b->data + b->byte_len;

    n00b_ansi_parse_internal(ctx);
}

n00b_list_t(n00b_ansi_node_t *)
n00b_ansi_parser_results(n00b_ansi_ctx *ctx)
{
    n00b_list_t(n00b_ansi_node_t *) new_list = n00b_list_new(n00b_ansi_node_t *);
    n00b_list_t(n00b_ansi_node_t *) result   = ctx->results;

    ctx->results = new_list;

    size_t len = n00b_list_len(result);

    if (len) {
        n00b_ansi_node_t *n = n00b_list_get(result, len - 1);
        if (n->kind == N00B_ANSI_PARTIAL) {
            (void)n00b_list_pop(n00b_ansi_node_t *, result);
            n00b_list_push(ctx->results, n);
        }
    }

    return result;
}

// -------------------------------------------------------------------
// Node-to-string conversion
// -------------------------------------------------------------------

static inline n00b_string_t *
one_node_to_string(n00b_ansi_node_t *node)
{
    char *p   = node->start;
    char *end = node->end;

    switch (node->kind) {
    case N00B_ANSI_CONTROL_SEQUENCE:
    case N00B_ANSI_PRIVATE_CONTROL:
    case N00B_ANSI_NF_SEQUENCE:
    case N00B_ANSI_FP_SEQUENCE:
    case N00B_ANSI_FE_SEQUENCE:
    case N00B_ANSI_FS_SEQUENCE:
    case N00B_ANSI_CTL_STR_CHAR:
    case N00B_ANSI_CRL_STR_CMD:
        while (*p != '\x1b') {
            p -= 1;
        }
        break;
    case N00B_ANSI_C0_CODE:
    case N00B_ANSI_C1_CODE:
        if (node->ctrl.ctrl_byte == '\r') {
            return n00b_string_from_raw("", 0);
        }
        return n00b_unicode_str_from_codepoint(node->ctrl.ctrl_byte);
    default:
        break;
    }

    int len = (int)(end - p);
    if (len <= 0) {
        return n00b_string_from_raw("", 0);
    }

    return n00b_string_from_raw(p, len);
}

n00b_string_t *
n00b_ansi_nodes_to_string(
    n00b_list_t(n00b_ansi_node_t *) nodes, bool keep_control) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;

    size_t         num = n00b_list_len(nodes);
    n00b_string_t *acc = n00b_string_from_raw("", 0, .allocator = allocator);

    for (size_t i = 0; i < num; i++) {
        n00b_ansi_node_t *node = n00b_list_get(nodes, i);
        n00b_string_t    *piece;

        if (keep_control) {
            piece = one_node_to_string(node);
        }
        else {
            switch (node->kind) {
            case N00B_ANSI_TEXT:
                piece = one_node_to_string(node);
                break;
            case N00B_ANSI_C0_CODE:
                switch (node->ctrl.ctrl_byte) {
                case '\n':
                    piece = n00b_string_from_raw("\n", 1, .allocator = allocator);
                    break;
                case '\t':
                    piece = n00b_string_from_raw("\t", 1, .allocator = allocator);
                    break;
                default:
                    continue;
                }
                break;
            default:
                continue;
            }
        }

        acc = n00b_unicode_str_cat(acc, piece, .allocator = allocator);
    }

    return acc;
}

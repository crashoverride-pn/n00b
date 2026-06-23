// pprint.c — slay pretty-printer (ported from slop/src/slay/pprint.c).
//
// Two-phase Wadler/Lindig algorithm:
//   Phase 1 — walk the parse tree and emit a document command
//             stream (DOC_TEXT, DOC_SPACE, DOC_SOFTLINE,
//             DOC_HARDLINE, DOC_BLANKLINE, DOC_INDENT,
//             DOC_DEDENT, DOC_GROUP_BEGIN/END, DOC_ALIGN_BEGIN/END).
//   Phase 2 — resolve the document stream into final output. For
//             each DOC_GROUP_BEGIN, measure the flat width of the
//             enclosed sub-document; if it fits in the remaining
//             columns at `line_width`, render flat (softlines
//             become spaces); otherwise render broken (softlines
//             become newlines at the current indent level).
//
// The port replaces slop's plain-C primitives with libn00b types:
//   - slop's `slay_tree_t` / `slay_grammar_t` -> n00b's
//     `n00b_parse_tree_t` / `n00b_grammar_t`.
//   - slop's `base_buf_t` -> n00b's `n00b_buffer_t`.
//   - slop's raw growable `slay_doc_cmd_t *` array -> n00b's
//     `n00b_list_t(n00b_pp_doc_cmd_t *)`.
//   - slop's `slay_annotation_t` enum (incl. SLAY_ROLE_BY_INDEX) ->
//     n00b's `n00b_annot_kind_t` / `n00b_role_kind_t`.
//
// The annotation surface and the kinds of per-child precision are
// the same shape as slop's, so the algorithm carries over almost
// verbatim. The only narrowing is that we currently honor
// per-child annotations only when the child reference is
// `N00B_ROLE_BY_INDEX`; name-based references would require a
// different mapping (resolve name -> child position via the rule's
// match items) which is out of scope for WP-006. The pretty-printer
// is annotation-driven; no programmatic style override is exposed.

#include "slay/pprint.h"
#include "internal/slay/grammar_internal.h"
#include "adt/list.h"
#include "adt/option.h"
#include "adt/stack.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"

#include <stdint.h>
#include <string.h>

// ============================================================================
// Document command kinds + struct
// ============================================================================

typedef enum {
    N00B_PP_DOC_TEXT,        // literal text segment
    N00B_PP_DOC_SPACE,       // single space
    N00B_PP_DOC_SOFTLINE,    // space (flat) | newline + indent (broken)
    N00B_PP_DOC_HARDLINE,    // unconditional newline + indent
    N00B_PP_DOC_BLANKLINE,   // two newlines + indent
    N00B_PP_DOC_INDENT,      // push indent stack
    N00B_PP_DOC_DEDENT,      // pop indent stack
    N00B_PP_DOC_GROUP_BEGIN, // start group; flat-fit attempt
    N00B_PP_DOC_GROUP_END,   // end group
    N00B_PP_DOC_ALIGN_BEGIN, // align to current column
    N00B_PP_DOC_ALIGN_END,   // pop alignment
} n00b_pp_doc_kind_t;

typedef struct {
    n00b_pp_doc_kind_t  kind;
    n00b_string_t      *text;   // for DOC_TEXT; nullptr otherwise
} n00b_pp_doc_cmd_t;

// ============================================================================
// Emission helpers — Phase 1 (document command stream)
// ============================================================================

static n00b_pp_doc_cmd_t *
pp_alloc_cmd(n00b_allocator_t *allocator,
             n00b_pp_doc_kind_t kind,
             n00b_string_t *text)
{
    n00b_pp_doc_cmd_t *c = n00b_alloc(n00b_pp_doc_cmd_t,
                                       .allocator = allocator);
    c->kind = kind;
    c->text = text;
    return c;
}

static void
pp_emit(n00b_list_t(n00b_pp_doc_cmd_t *) *ds,
        n00b_allocator_t *allocator,
        n00b_pp_doc_kind_t kind,
        n00b_string_t *text)
{
    n00b_list_push(*ds, pp_alloc_cmd(allocator, kind, text));
}

// ============================================================================
// Annotation summary for an NT (mirrors slop's `annot_summary_t`).
//
// Per-child index sets use dynamic lists so there is no fixed cap on the
// number of `@hardline` / `@softline` / `@nospace` / `@align` annotations
// a single NT may carry. The lists are private (single-thread, no lock)
// and inherit the caller's allocator so an arena-mode caller sees all
// scratch live under their arena.
// ============================================================================

typedef struct {
    bool                  indent;
    bool                  group;
    bool                  concat;
    bool                  blankline;
    n00b_list_t(int32_t)  softline_before;
    n00b_list_t(int32_t)  hardline_before;
    n00b_list_t(int32_t)  nospace_before;
    n00b_list_t(int32_t)  align_to;
} n00b_pp_annot_summary_t;

static n00b_pp_annot_summary_t
pp_read_annotations(n00b_nonterm_t *nt, n00b_allocator_t *allocator)
{
    n00b_pp_annot_summary_t s = {
        .softline_before = n00b_list_new_private(int32_t,
                                                  .allocator = allocator),
        .hardline_before = n00b_list_new_private(int32_t,
                                                  .allocator = allocator),
        .nospace_before  = n00b_list_new_private(int32_t,
                                                  .allocator = allocator),
        .align_to        = n00b_list_new_private(int32_t,
                                                  .allocator = allocator),
    };

    if (!nt || !nt->pending_annotations.data) {
        return s;
    }

    size_t n = n00b_list_len(nt->pending_annotations);

    for (size_t i = 0; i < n; i++) {
        n00b_annotation_t *a = n00b_list_get(nt->pending_annotations, i);

        if (!a) {
            continue;
        }

        switch (a->kind) {
        case N00B_ANNOT_INDENT:
            s.indent = true;
            break;

        case N00B_ANNOT_GROUP:
            s.group = true;
            break;

        case N00B_ANNOT_CONCAT:
            s.concat = true;
            break;

        case N00B_ANNOT_BLANKLINE:
            s.blankline = true;
            break;

        case N00B_ANNOT_SOFTLINE:
            if (a->name_ref.kind == N00B_ROLE_BY_INDEX
                    && a->name_ref.index >= 0) {
                n00b_list_push(s.softline_before, (int32_t)a->name_ref.index);
            }
            break;

        case N00B_ANNOT_HARDLINE:
            if (a->name_ref.kind == N00B_ROLE_BY_INDEX
                    && a->name_ref.index >= 0) {
                n00b_list_push(s.hardline_before, (int32_t)a->name_ref.index);
            }
            break;

        case N00B_ANNOT_NOSPACE:
            if (a->name_ref.kind == N00B_ROLE_BY_INDEX
                    && a->name_ref.index >= 0) {
                n00b_list_push(s.nospace_before, (int32_t)a->name_ref.index);
            }
            break;

        case N00B_ANNOT_ALIGN:
            if (a->name_ref.kind == N00B_ROLE_BY_INDEX
                    && a->name_ref.index >= 0) {
                n00b_list_push(s.align_to, (int32_t)a->name_ref.index);
            }
            break;

        default:
            break;
        }
    }

    return s;
}

static bool
pp_in_index_list(n00b_list_t(int32_t) *lst, int32_t ix)
{
    if (!lst || !lst->data) {
        return false;
    }

    size_t n = n00b_list_len(*lst);
    for (size_t i = 0; i < n; i++) {
        if (n00b_list_get(*lst, i) == ix) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// Default token-adjacency spacing heuristics
// ============================================================================

typedef enum {
    N00B_PP_TOK_OPEN_BRACKET,
    N00B_PP_TOK_CLOSE_BRACKET,
    N00B_PP_TOK_COMMA,
    N00B_PP_TOK_SEMICOLON,
    N00B_PP_TOK_DOT,
    N00B_PP_TOK_OTHER,
} n00b_pp_tok_cat_t;

static n00b_pp_tok_cat_t
pp_categorize(const char *bytes, size_t len)
{
    if (!bytes || len == 0) {
        return N00B_PP_TOK_OTHER;
    }

    char c0 = bytes[0];

    if (len == 1) {
        if (c0 == '(' || c0 == '[' || c0 == '{') {
            return N00B_PP_TOK_OPEN_BRACKET;
        }
        if (c0 == ')' || c0 == ']' || c0 == '}') {
            return N00B_PP_TOK_CLOSE_BRACKET;
        }
        if (c0 == ',') {
            return N00B_PP_TOK_COMMA;
        }
        if (c0 == ';') {
            return N00B_PP_TOK_SEMICOLON;
        }
        if (c0 == '.') {
            return N00B_PP_TOK_DOT;
        }
    }
    else if (len == 2 && c0 == '-' && bytes[1] == '>') {
        return N00B_PP_TOK_DOT;
    }

    return N00B_PP_TOK_OTHER;
}

static bool
pp_heuristic_space(n00b_pp_tok_cat_t prev, n00b_pp_tok_cat_t next)
{
    if (prev == N00B_PP_TOK_OPEN_BRACKET) {
        return false;
    }
    if (next == N00B_PP_TOK_CLOSE_BRACKET) {
        return false;
    }
    if (next == N00B_PP_TOK_COMMA) {
        return false;
    }
    if (next == N00B_PP_TOK_SEMICOLON) {
        return false;
    }
    if (prev == N00B_PP_TOK_DOT) {
        return false;
    }
    if (next == N00B_PP_TOK_DOT) {
        return false;
    }
    return true;
}

// ============================================================================
// Emit context (Phase 1)
// ============================================================================

typedef struct {
    n00b_list_t(n00b_pp_doc_cmd_t *) *ds;
    n00b_allocator_t                 *allocator;
    n00b_grammar_t                   *grammar;
    n00b_pp_tok_cat_t                 last_tok_cat;
    bool                              need_space;  // next token needs leading space
    bool                              first_token; // suppress space before first
} n00b_pp_emit_ctx_t;

// ============================================================================
// Trivia emission
// ============================================================================

static void
pp_emit_trivia(n00b_pp_emit_ctx_t *ctx, n00b_trivia_t *trivia)
{
    n00b_trivia_t *t;
    for (t = trivia; t; t = t->next) {
        if (t->text && t->text->u8_bytes > 0) {
            pp_emit(ctx->ds, ctx->allocator, N00B_PP_DOC_TEXT, t->text);
        }
    }
}

// ============================================================================
// Tree walk: emit document commands
// ============================================================================

static void pp_emit_tree(n00b_pp_emit_ctx_t *ctx, n00b_parse_tree_t *node);

static void
pp_emit_token(n00b_pp_emit_ctx_t *ctx, n00b_token_info_t *tok)
{
    if (!tok || !n00b_option_is_set(tok->value)) {
        return;
    }

    n00b_string_t *val = n00b_option_get(tok->value);

    if (!val || val->u8_bytes == 0) {
        return;
    }

    n00b_pp_tok_cat_t cat = pp_categorize(val->data, val->u8_bytes);

    if (tok->leading_trivia) {
        // If leading trivia exists, emit it and suppress document-model
        // spacing — the trivia already carries the user's whitespace.
        pp_emit_trivia(ctx, tok->leading_trivia);
        ctx->need_space = false;
    }
    else if (!ctx->first_token && ctx->need_space
                && pp_heuristic_space(ctx->last_tok_cat, cat)) {
        pp_emit(ctx->ds, ctx->allocator, N00B_PP_DOC_SPACE, nullptr);
    }

    pp_emit(ctx->ds, ctx->allocator, N00B_PP_DOC_TEXT, val);

    ctx->first_token  = false;
    ctx->need_space   = true;
    ctx->last_tok_cat = cat;

    if (tok->trailing_trivia) {
        pp_emit_trivia(ctx, tok->trailing_trivia);
    }
}

static void
pp_emit_nt(n00b_pp_emit_ctx_t *ctx, n00b_parse_tree_t *node)
{
    n00b_nt_node_t *pn   = &n00b_tree_node_value(node);
    n00b_nonterm_t *nt   = n00b_get_nonterm(ctx->grammar, pn->id);

    n00b_pp_annot_summary_t s = pp_read_annotations(nt, ctx->allocator);

    bool do_indent = s.indent;
    bool do_group  = s.group;
    bool do_concat = s.concat;
    bool do_blank  = s.blankline;

    if (do_group) {
        pp_emit(ctx->ds, ctx->allocator, N00B_PP_DOC_GROUP_BEGIN, nullptr);
    }

    size_t nc = n00b_tree_num_children(node);

    // Last hardline child index — so we can dedent before it, putting
    // the closing delimiter at the parent's indent level (matches the
    // slop reference).
    int32_t last_hardline_child = -1;

    if (do_indent) {
        size_t hn = n00b_list_len(s.hardline_before);
        for (size_t k = 0; k < hn; k++) {
            int32_t h = n00b_list_get(s.hardline_before, k);
            if (h > last_hardline_child) {
                last_hardline_child = h;
            }
        }
    }

    if (do_indent) {
        pp_emit(ctx->ds, ctx->allocator, N00B_PP_DOC_INDENT, nullptr);
    }

    bool saved_need_space = ctx->need_space;
    bool did_dedent       = false;

    if (do_concat) {
        ctx->need_space = false;
    }

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_tree_child(node, i);

        if (!child) {
            continue;
        }

        // Skip "missing" parse-error placeholders.
        if (!n00b_tree_is_leaf(child)) {
            n00b_nt_node_t *cpn = &n00b_tree_node_value(child);
            if (cpn->missing) {
                continue;
            }
        }

        int32_t ci = (int32_t)i;

        // Dedent before the final hardline so a closing delimiter
        // lands at parent indent (e.g., `}` after a block body).
        if (do_indent && !did_dedent && ci == last_hardline_child) {
            pp_emit(ctx->ds, ctx->allocator, N00B_PP_DOC_DEDENT, nullptr);
            did_dedent = true;
        }

        if (pp_in_index_list(&s.hardline_before, ci)) {
            pp_emit(ctx->ds, ctx->allocator, N00B_PP_DOC_HARDLINE, nullptr);
            ctx->need_space = false;
        }
        else if (pp_in_index_list(&s.softline_before, ci)) {
            pp_emit(ctx->ds, ctx->allocator, N00B_PP_DOC_SOFTLINE, nullptr);
            ctx->need_space = false;
        }

        if (pp_in_index_list(&s.nospace_before, ci)) {
            ctx->need_space = false;
        }

        bool align = pp_in_index_list(&s.align_to, ci);

        if (align) {
            pp_emit(ctx->ds, ctx->allocator, N00B_PP_DOC_ALIGN_BEGIN, nullptr);
        }

        pp_emit_tree(ctx, child);

        if (align) {
            pp_emit(ctx->ds, ctx->allocator, N00B_PP_DOC_ALIGN_END, nullptr);
        }

        if (do_concat) {
            ctx->need_space = false;
        }
    }

    if (do_indent && !did_dedent) {
        pp_emit(ctx->ds, ctx->allocator, N00B_PP_DOC_DEDENT, nullptr);
    }

    if (do_group) {
        pp_emit(ctx->ds, ctx->allocator, N00B_PP_DOC_GROUP_END, nullptr);
    }

    if (do_blank) {
        pp_emit(ctx->ds, ctx->allocator, N00B_PP_DOC_BLANKLINE, nullptr);
    }

    if (do_concat) {
        ctx->need_space = saved_need_space;
    }
}

static void
pp_emit_tree(n00b_pp_emit_ctx_t *ctx, n00b_parse_tree_t *node)
{
    if (!node) {
        return;
    }

    if (n00b_tree_is_leaf(node)) {
        n00b_token_info_t *tok = n00b_tree_leaf_value(node);
        pp_emit_token(ctx, tok);
        return;
    }

    n00b_nt_node_t *pn = &n00b_tree_node_value(node);

    if (pn->missing) {
        return;
    }

    // Group nodes (synthetic `$$group_N` from BNF quantifiers, or
    // group-top markers) are transparent — recurse into their
    // children without applying annotation-driven formatting on
    // the synthetic NT.
    if (pn->group_top || pn->group_item || n00b_pt_is_group(node)) {
        size_t nc = n00b_tree_num_children(node);
        for (size_t i = 0; i < nc; i++) {
            pp_emit_tree(ctx, n00b_tree_child(node, i));
        }
        return;
    }

    pp_emit_nt(ctx, node);
}

// ============================================================================
// Buffer append helpers (Phase 2 output)
// ============================================================================

static void
pp_append_bytes(n00b_buffer_t *buf, const char *bytes, size_t len)
{
    if (!buf || !bytes || len == 0) {
        return;
    }

    size_t old = buf->byte_len;
    n00b_buffer_resize(buf, (uint64_t)(old + len));
    memcpy(buf->data + old, bytes, len);
}

static void
pp_append_char(n00b_buffer_t *buf, char c)
{
    pp_append_bytes(buf, &c, 1);
}

static void
pp_append_string(n00b_buffer_t *buf, n00b_string_t *s)
{
    if (!s) {
        return;
    }
    pp_append_bytes(buf, s->data, s->u8_bytes);
}

// Width of an emitted text segment, in display columns. We use
// codepoint count as a proxy (libn00b strings precount codepoints).
// Full double-width / zero-width handling is a future refinement —
// see the preflight's note on Unicode width.
static int64_t
pp_text_width(n00b_string_t *s)
{
    if (!s) {
        return 0;
    }
    return (int64_t)s->codepoints;
}

// ============================================================================
// Indent emission
// ============================================================================

static void
pp_emit_indent(n00b_buffer_t *buf,
               int32_t level,
               int64_t indent_size,
               bool indent_tabs)
{
    if (level <= 0) {
        return;
    }

    if (indent_tabs) {
        // One tab per level.
        for (int32_t i = 0; i < level; i++) {
            pp_append_char(buf, '\t');
        }
    }
    else {
        int64_t total = (int64_t)level * indent_size;
        for (int64_t i = 0; i < total; i++) {
            pp_append_char(buf, ' ');
        }
    }
}

// Logical column delta from emitting indent at this level.
static int64_t
pp_indent_column(int32_t level, int64_t indent_size, bool indent_tabs)
{
    if (level <= 0) {
        return 0;
    }
    if (indent_tabs) {
        // For column tracking under tabs, treat each tab as
        // `indent_size` columns. (Same heuristic as slop.)
        return (int64_t)level * indent_size;
    }
    return (int64_t)level * indent_size;
}

// ============================================================================
// Phase 2 — measure flat width of a sub-document
// ============================================================================

// Returns INT64_MAX if a hardline/blankline forces the group to break.
static int64_t
pp_measure_flat_width(n00b_list_t(n00b_pp_doc_cmd_t *) *ds,
                      int32_t start,
                      int32_t end)
{
    int64_t width = 0;
    int     depth = 0;

    size_t total = n00b_list_len(*ds);

    if (end > (int32_t)total) {
        end = (int32_t)total;
    }

    for (int32_t i = start; i < end; i++) {
        n00b_pp_doc_cmd_t *c = n00b_list_get(*ds, i);

        if (!c) {
            continue;
        }

        switch (c->kind) {
        case N00B_PP_DOC_TEXT:
            width += pp_text_width(c->text);
            break;
        case N00B_PP_DOC_SPACE:
        case N00B_PP_DOC_SOFTLINE:
            width += 1;
            break;
        case N00B_PP_DOC_HARDLINE:
        case N00B_PP_DOC_BLANKLINE:
            return INT64_MAX;
        case N00B_PP_DOC_GROUP_BEGIN:
            depth++;
            break;
        case N00B_PP_DOC_GROUP_END:
            depth--;
            if (depth < 0) {
                return width;
            }
            break;
        default:
            break;
        }
    }

    return width;
}

// Find the index of the matching GROUP_END for the GROUP_BEGIN at `start`.
static int32_t
pp_find_group_end(n00b_list_t(n00b_pp_doc_cmd_t *) *ds, int32_t start)
{
    int     depth = 1;
    int32_t count = (int32_t)n00b_list_len(*ds);

    for (int32_t i = start + 1; i < count; i++) {
        n00b_pp_doc_cmd_t *c = n00b_list_get(*ds, i);

        if (!c) {
            continue;
        }

        if (c->kind == N00B_PP_DOC_GROUP_BEGIN) {
            depth++;
        }
        else if (c->kind == N00B_PP_DOC_GROUP_END) {
            depth--;
            if (depth == 0) {
                return i;
            }
        }
    }

    return count;
}

// ============================================================================
// Phase 2 — layout resolution
//
// Layout state uses three dynamic stacks (private — single-threaded —
// and routed through the caller's allocator). Each stack is primed with
// a sentinel bottom element so `peek` is always well-defined: the
// original fixed-size code relied on `*_stack[0]` being readable even
// when `*_top == 0`. With `n00b_stack_t`, the equivalent invariant is
// that pop requests below the sentinel are no-ops (`stack_len > 1`).
// ============================================================================

static n00b_buffer_t *
pp_layout_resolve(n00b_list_t(n00b_pp_doc_cmd_t *) *ds,
                  n00b_allocator_t                 *allocator,
                  int64_t                           line_width,
                  int64_t                           indent_size,
                  bool                              indent_tabs,
                  n00b_string_t                    *newline)
{
    n00b_buffer_t *ob = n00b_buffer_empty(.allocator = allocator);

    n00b_stack_t(int32_t) indent_stack
        = n00b_stack_new(int32_t, false, .allocator = allocator);
    n00b_stack_push(indent_stack, (int32_t)0);

    // group_mode top: true = broken (softlines -> newlines),
    //                 false = flat (softlines -> spaces).
    // Outermost is "broken" by default — matches slop's behavior of
    // emitting hardlines as newlines outside any explicit group.
    n00b_stack_t(bool) group_mode
        = n00b_stack_new(bool, false, .allocator = allocator);
    n00b_stack_push(group_mode, true);

    n00b_stack_t(int32_t) align_stack
        = n00b_stack_new(int32_t, false, .allocator = allocator);
    n00b_stack_push(align_stack, (int32_t)0);

    int64_t col = 0;
    int32_t count = (int32_t)n00b_list_len(*ds);

    for (int32_t i = 0; i < count; i++) {
        n00b_pp_doc_cmd_t *cmd = n00b_list_get(*ds, i);

        if (!cmd) {
            continue;
        }

        switch (cmd->kind) {
        case N00B_PP_DOC_TEXT:
            pp_append_string(ob, cmd->text);
            col += pp_text_width(cmd->text);
            break;

        case N00B_PP_DOC_SPACE:
            pp_append_char(ob, ' ');
            col++;
            break;

        case N00B_PP_DOC_SOFTLINE:
            if (n00b_stack_len(group_mode) > 1 && !n00b_stack_peek(group_mode)) {
                pp_append_char(ob, ' ');
                col++;
            }
            else {
                pp_append_string(ob, newline);
                col = 0;
                int32_t ind = n00b_stack_peek(indent_stack);
                pp_emit_indent(ob, ind, indent_size, indent_tabs);
                col = pp_indent_column(ind, indent_size, indent_tabs);
            }
            break;

        case N00B_PP_DOC_HARDLINE: {
            pp_append_string(ob, newline);
            col = 0;
            int32_t ind = n00b_stack_peek(indent_stack);
            pp_emit_indent(ob, ind, indent_size, indent_tabs);
            col = pp_indent_column(ind, indent_size, indent_tabs);
            break;
        }

        case N00B_PP_DOC_BLANKLINE: {
            pp_append_string(ob, newline);
            pp_append_string(ob, newline);
            col = 0;
            int32_t ind = n00b_stack_peek(indent_stack);
            pp_emit_indent(ob, ind, indent_size, indent_tabs);
            col = pp_indent_column(ind, indent_size, indent_tabs);
            break;
        }

        case N00B_PP_DOC_INDENT: {
            int32_t cur = n00b_stack_peek(indent_stack);
            n00b_stack_push(indent_stack, (int32_t)(cur + 1));
            break;
        }

        case N00B_PP_DOC_DEDENT:
            if (n00b_stack_len(indent_stack) > 1) {
                (void)n00b_stack_pop(int32_t, indent_stack);
            }
            break;

        case N00B_PP_DOC_GROUP_BEGIN: {
            int32_t end    = pp_find_group_end(ds, i);
            int64_t flat_w = pp_measure_flat_width(ds, i + 1, end);

            // Break this group if it can't fit flat in the
            // remaining line.
            n00b_stack_push(group_mode, (bool)(col + flat_w > line_width));
            break;
        }

        case N00B_PP_DOC_GROUP_END:
            if (n00b_stack_len(group_mode) > 1) {
                (void)n00b_stack_pop(bool, group_mode);
            }
            break;

        case N00B_PP_DOC_ALIGN_BEGIN:
            n00b_stack_push(align_stack, (int32_t)col);
            break;

        case N00B_PP_DOC_ALIGN_END:
            if (n00b_stack_len(align_stack) > 1) {
                (void)n00b_stack_pop(int32_t, align_stack);
            }
            break;
        }
    }

    return ob;
}

// ============================================================================
// Error-string accessor
// ============================================================================

n00b_string_t *
n00b_pretty_print_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_ERR_PPRINT_NULL_INPUT:
        return r"n00b_pretty_print: null grammar or null tree";
    case N00B_ERR_PPRINT_INTERNAL:
        return r"n00b_pretty_print: internal failure";
    default:
        return r"n00b_pretty_print: (unknown)";
    }
}

// ============================================================================
// Public API: n00b_pretty_print
// ============================================================================

n00b_result_t(n00b_string_t *)
n00b_pretty_print(n00b_grammar_t *g, n00b_parse_tree_t *tree) _kargs
{
    int64_t           line_width  = 80;
    int64_t           indent_size = 4;
    bool              indent_tabs = false;
    n00b_string_t    *newline     = nullptr;
    n00b_allocator_t *allocator   = nullptr;
}
{
    if (!g || !tree) {
        return n00b_result_err(n00b_string_t *, N00B_ERR_PPRINT_NULL_INPUT);
    }

    if (line_width <= 0) {
        line_width = 80;
    }
    if (indent_size <= 0) {
        indent_size = 4;
    }
    if (!newline) {
        newline = r"\n";
    }

    n00b_list_t(n00b_pp_doc_cmd_t *) ds_val =
        n00b_list_new_private(n00b_pp_doc_cmd_t *, .allocator = allocator);

    n00b_pp_emit_ctx_t ctx = {
        .ds           = &ds_val,
        .allocator    = allocator,
        .grammar      = g,
        .last_tok_cat = N00B_PP_TOK_OTHER,
        .need_space   = false,
        .first_token  = true,
    };

    pp_emit_tree(&ctx, tree);

    n00b_buffer_t *ob = pp_layout_resolve(&ds_val,
                                          allocator,
                                          line_width,
                                          indent_size,
                                          indent_tabs,
                                          newline);

    n00b_string_t *out = n00b_string_from_raw(ob->data,
                                              (int64_t)ob->byte_len,
                                              .allocator = allocator);

    return n00b_result_ok(n00b_string_t *, out);
}

// bnf.c - BNF grammar-from-text parser
//
// Uses a custom tokenizer to avoid character-level ambiguity with
// quoted string literals.  The BNF meta-grammar then operates on
// tokens rather than individual characters.
//
// Uses the pluggable n00b_parse_fn_t abstraction; defaults to PWZ.

#include "slay/bnf.h"
#include "slay/pwz.h"
#include "slay/rewrite.h"
#include "n00b/n00b_tokenizer.h"
#include "internal/slay/grammar_internal.h"
#include "text/strings/string_ops.h"
#include "parsers/scanner.h"
#include "parsers/scan_recipes.h"
#include "parsers/token_stream.h"
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Simple UTF-8 decoder for grammar literals
// ============================================================================

static int32_t
utf8_decode(const char **pp)
{
    const unsigned char *p = (const unsigned char *)*pp;
    int32_t              cp;

    if (*p < 0x80) {
        cp = *p++;
    }
    else if (*p < 0xE0) {
        cp  = (*p++ & 0x1F) << 6;
        cp |= *p++ & 0x3F;
    }
    else if (*p < 0xF0) {
        cp  = (*p++ & 0x0F) << 12;
        cp |= (*p++ & 0x3F) << 6;
        cp |= *p++ & 0x3F;
    }
    else {
        cp  = (*p++ & 0x07) << 18;
        cp |= (*p++ & 0x3F) << 12;
        cp |= (*p++ & 0x3F) << 6;
        cp |= *p++ & 0x3F;
    }

    *pp = (const char *)p;
    return cp;
}

// ============================================================================
// Preprocessing
// ============================================================================

n00b_string_t *
n00b_bnf_strip_comments(n00b_string_t *input)
{
    if (!input) {
        return n00b_string_empty();
    }

    size_t      len    = input->u8_bytes;
    const char *src    = input->data;
    char       *result = n00b_alloc_array(char, len + 1);
    size_t      ri     = 0;
    bool        in_sq  = false;
    bool        in_dq  = false;

    for (size_t i = 0; i < len; i++) {
        char c = src[i];

        if (c == '\'' && !in_dq) {
            in_sq = !in_sq;
        }
        else if (c == '"' && !in_sq) {
            in_dq = !in_dq;
        }

        if (c == '#' && !in_sq && !in_dq) {
            while (i < len && src[i] != '\n') {
                i++;
            }

            if (i < len) {
                result[ri++] = '\n';
            }

            continue;
        }

        result[ri++] = c;
    }

    result[ri] = '\0';

    return n00b_string_from_raw(result, (int64_t)ri);
}

n00b_string_t *
n00b_bnf_trim_lines(n00b_string_t *input)
{
    if (!input) {
        return n00b_string_empty();
    }

    size_t      len    = input->u8_bytes;
    const char *src    = input->data;
    const char *end    = src + len;
    char       *result = n00b_alloc_array(char, len + 1);
    size_t      ri     = 0;
    const char *p      = src;

    while (p < end) {
        while (p < end && *p != '\n' && (*p == ' ' || *p == '\t')) {
            p++;
        }

        const char *line_start = p;

        while (p < end && *p != '\n') {
            p++;
        }

        const char *line_end = p;

        while (line_end > line_start
               && (line_end[-1] == ' ' || line_end[-1] == '\t'
                   || line_end[-1] == '\r')) {
            line_end--;
        }

        size_t line_len = (size_t)(line_end - line_start);
        memcpy(result + ri, line_start, line_len);
        ri += line_len;

        if (p < end && *p == '\n') {
            result[ri++] = '\n';
            p++;
        }
    }

    result[ri] = '\0';

    return n00b_string_from_raw(result, (int64_t)ri);
}

// ============================================================================
// Join continuation lines: remove newlines before lines starting with '|'
// ============================================================================

static n00b_string_t *
bnf_join_continuations(n00b_string_t *input)
{
    if (!input) {
        return n00b_string_empty();
    }

    size_t      len    = input->u8_bytes;
    const char *src    = input->data;
    char       *result = n00b_alloc_array(char, len + 1);
    size_t      ri     = 0;

    for (size_t i = 0; i < len; i++) {
        if (src[i] == '\n') {
            // Look ahead past whitespace AND blank lines to see if the
            // next non-blank character is '|'.
            size_t j = i + 1;

            while (j < len
                   && (src[j] == ' ' || src[j] == '\t' || src[j] == '\n'
                       || src[j] == '\r')) {
                j++;
            }

            if (j < len && src[j] == '|') {
                // Replace newline (and any intervening blank lines)
                // with a space; the trimmer already removed leading
                // whitespace, but we add a separator.
                result[ri++] = ' ';
                i = j - 1;  // loop increment will advance past whitespace
                continue;
            }
        }

        result[ri++] = src[i];
    }

    result[ri] = '\0';

    return n00b_string_from_raw(result, (int64_t)ri);
}

// ============================================================================
// BNF Tokenizer
// ============================================================================

// Token IDs for the BNF meta-grammar (internal, local base).
enum {
    BNF_TOK_BASE          = 100,
    BNF_TOK_LANGLE        = BNF_TOK_BASE + 1,   // <
    BNF_TOK_RANGLE        = BNF_TOK_BASE + 2,   // >
    BNF_TOK_ASSIGN        = BNF_TOK_BASE + 3,   // ::=
    BNF_TOK_PIPE          = BNF_TOK_BASE + 4,   // |
    BNF_TOK_NEWLINE       = BNF_TOK_BASE + 5,   // \n
    BNF_TOK_NAME          = BNF_TOK_BASE + 6,   // rule name
    BNF_TOK_LITERAL       = BNF_TOK_BASE + 7,   // quoted literal
    BNF_TOK_CLASS         = BNF_TOK_BASE + 8,   // __CLASS
    BNF_TOK_TOKEN_TYPE    = BNF_TOK_BASE + 9,   // %NAME (token type)
    BNF_TOK_TOKEN_LIT     = BNF_TOK_BASE + 10,  // %"..." (token literal)
    BNF_TOK_EMPTY_LIT     = BNF_TOK_BASE + 11,  // "" (empty literal)
    BNF_TOK_QUESTION      = BNF_TOK_BASE + 12,  // ?
    BNF_TOK_STAR          = BNF_TOK_BASE + 13,  // *
    BNF_TOK_PLUS_OP       = BNF_TOK_BASE + 14,  // +
    BNF_TOK_LPAREN        = BNF_TOK_BASE + 15,  // (
    BNF_TOK_RPAREN        = BNF_TOK_BASE + 16,  // )
    BNF_TOK_AT            = BNF_TOK_BASE + 17,  // @
    BNF_TOK_DOLLAR        = BNF_TOK_BASE + 18,  // $N (digit in value)
    BNF_TOK_COMMA         = BNF_TOK_BASE + 19,  // ,
    BNF_TOK_CAPTURE_DECL  = BNF_TOK_BASE + 20,  // $name: (inline capture)
    BNF_TOK_REWRITE_BLOCK = BNF_TOK_BASE + 21,  // {=* ... =*} (rewrite body)
};

// ============================================================================
// BNF scanner callback (replaces hand-rolled tokenizer)
// ============================================================================

static bool
is_bnf_hws(n00b_codepoint_t cp, void *ctx)
{
    (void)ctx;
    return cp == ' ' || cp == '\t';
}

static bool
bnf_scan(n00b_scanner_t *s)
{
    bool *in_angle = (bool *)s->user_state;

    // Skip horizontal whitespace (spaces and tabs, not newlines).
    n00b_scan_skip_while(s, is_bnf_hws);

    if (n00b_scan_at_eof(s)) {
        return false;
    }

    n00b_codepoint_t ch = n00b_scan_peek(s, 0);

    // Newline (\r\n or \n).
    if (ch == '\r' || ch == '\n') {
        n00b_scan_mark(s);

        if (ch == '\r' && n00b_scan_peek_byte(s, 1) == '\n') {
            n00b_scan_advance(s);
        }

        n00b_scan_advance(s);
        n00b_scan_emit(s, .tid = BNF_TOK_NEWLINE);
        return true;
    }

    // ::=
    if (ch == ':') {
        n00b_scan_mark(s);

        if (n00b_scan_match_str(s, "::=")) {
            n00b_scan_emit(s, .tid = BNF_TOK_ASSIGN);
            return true;
        }

        // Not "::=", skip the lone colon.
        n00b_scan_advance(s);
        return true;
    }

    // < and >
    if (ch == '<') {
        n00b_scan_mark(s);
        n00b_scan_advance(s);
        n00b_scan_emit(s, .tid = BNF_TOK_LANGLE);
        *in_angle = true;
        return true;
    }

    if (ch == '>') {
        n00b_scan_mark(s);
        n00b_scan_advance(s);
        n00b_scan_emit(s, .tid = BNF_TOK_RANGLE);
        *in_angle = false;
        return true;
    }

    // |
    if (ch == '|') {
        n00b_scan_mark(s);
        n00b_scan_advance(s);
        n00b_scan_emit(s, .tid = BNF_TOK_PIPE);
        return true;
    }

    // Token terminal: %NAME or %"..." or %'...'
    if (ch == '%') {
        n00b_scan_advance(s);  // skip '%'

        n00b_codepoint_t next = n00b_scan_peek(s, 0);

        if (next == '"' || next == '\'') {
            // %"..." or %'...' — token literal
            n00b_codepoint_t quote = next;
            n00b_scan_advance(s);  // skip opening quote
            n00b_scan_mark(s);     // mark start of content

            while (!n00b_scan_at_eof(s)) {
                n00b_codepoint_t c = n00b_scan_peek(s, 0);

                if (c == quote || c == '\n') {
                    break;
                }

                n00b_scan_advance(s);
            }

            n00b_string_t *val = n00b_scan_extract(s);

            if (!n00b_scan_at_eof(s) && n00b_scan_peek(s, 0) == quote) {
                n00b_scan_advance(s);  // skip closing quote
            }

            n00b_scan_emit(s, .tid = BNF_TOK_TOKEN_LIT,
                           .contents = n00b_option_set(n00b_string_t *, val));
            return true;
        }

        if ((next >= 'a' && next <= 'z') || (next >= 'A' && next <= 'Z')
            || next == '_') {
            // %NAME — token type
            n00b_scan_mark(s);

            while (!n00b_scan_at_eof(s)) {
                n00b_codepoint_t c = n00b_scan_peek(s, 0);

                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                      || (c >= '0' && c <= '9') || c == '_')) {
                    break;
                }

                n00b_scan_advance(s);
            }

            n00b_string_t *val = n00b_scan_extract(s);
            n00b_scan_emit(s, .tid = BNF_TOK_TOKEN_TYPE,
                           .contents = n00b_option_set(n00b_string_t *, val));
            return true;
        }

        // Bare '%' with nothing recognizable after it — skip.
        return true;
    }

    // Quoted literal: "..." or '...'
    if (ch == '"' || ch == '\'') {
        n00b_codepoint_t quote = ch;
        n00b_scan_advance(s);  // skip opening quote
        n00b_scan_mark(s);     // mark start of content

        while (!n00b_scan_at_eof(s)) {
            n00b_codepoint_t c = n00b_scan_peek(s, 0);

            if (c == quote || c == '\n') {
                break;
            }

            n00b_scan_advance(s);
        }

        n00b_string_t *val = n00b_scan_extract(s);

        if (!n00b_scan_at_eof(s) && n00b_scan_peek(s, 0) == quote) {
            n00b_scan_advance(s);  // skip closing quote
        }

        int64_t tid = (!val || val->u8_bytes == 0) ? BNF_TOK_EMPTY_LIT : BNF_TOK_LITERAL;
        n00b_scan_emit(s, .tid = tid,
                       .contents = n00b_option_set(n00b_string_t *, val));
        return true;
    }

    // __CLASS (reserved terminal)
    if (ch == '_' && n00b_scan_peek_byte(s, 1) == '_') {
        uint8_t third = n00b_scan_peek_byte(s, 2);

        if ((third >= 'a' && third <= 'z') || (third >= 'A' && third <= 'Z')) {
            n00b_scan_mark(s);
            n00b_scan_advance(s);  // first '_'
            n00b_scan_advance(s);  // second '_'

            while (!n00b_scan_at_eof(s)) {
                n00b_codepoint_t c = n00b_scan_peek(s, 0);

                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                      || c == '_')) {
                    break;
                }

                n00b_scan_advance(s);
            }

            n00b_string_t *val = n00b_scan_extract(s);
            n00b_scan_emit(s, .tid = BNF_TOK_CLASS,
                           .contents = n00b_option_set(n00b_string_t *, val));
            return true;
        }
    }

    // Rule name: letter or '_' followed by letters, digits, '-', '_'
    // Inside <angle brackets>, also accept ',' as part of the name.
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_') {
        n00b_scan_mark(s);

        while (!n00b_scan_at_eof(s)) {
            n00b_codepoint_t c = n00b_scan_peek(s, 0);

            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                  || (c >= '0' && c <= '9') || c == '-' || c == '_'
                  || (*in_angle && c == ','))) {
                break;
            }

            n00b_scan_advance(s);
        }

        n00b_string_t *val = n00b_scan_extract(s);

        // Contextual keyword: `rewrite { ... }` starts a rewrite block.
        // We only swallow `rewrite` here if it is immediately followed
        // (modulo horizontal whitespace) by `{`. Otherwise it's a
        // regular identifier and we emit NAME as usual.
        if (!*in_angle && val->u8_bytes == 7
            && memcmp(val->data, "rewrite", 7) == 0) {
            n00b_scan_skip_while(s, is_bnf_hws);
            if (!n00b_scan_at_eof(s) && n00b_scan_peek(s, 0) == '{') {
                // Drop the "rewrite" identifier; fall through to the
                // brace-block handler below by skipping `{` here and
                // running the same body-scan loop the bare `{` branch
                // uses.
                n00b_scan_advance(s);  // skip `{`

                int level = 0;
                while (!n00b_scan_at_eof(s)
                       && n00b_scan_peek(s, 0) == '=') {
                    level++;
                    n00b_scan_advance(s);
                }

                n00b_scan_mark(s);

                bool found = false;
                while (!n00b_scan_at_eof(s)) {
                    if (n00b_scan_peek(s, 0) == '=') {
                        int eqs = 0;
                        while (n00b_scan_peek(s, eqs) == '=') {
                            eqs++;
                        }
                        if (eqs == level
                            && n00b_scan_peek(s, eqs) == '}') {
                            found = true;
                            break;
                        }
                    }
                    if (n00b_scan_peek(s, 0) == '}' && level == 0) {
                        found = true;
                        break;
                    }
                    n00b_scan_advance(s);
                }

                n00b_string_t *body = n00b_scan_extract(s);

                if (found) {
                    for (int i = 0; i < level; i++) {
                        n00b_scan_advance(s);
                    }
                    if (!n00b_scan_at_eof(s)
                        && n00b_scan_peek(s, 0) == '}') {
                        n00b_scan_advance(s);
                    }
                }

                n00b_scan_emit(
                    s, .tid     = BNF_TOK_REWRITE_BLOCK,
                    .contents = n00b_option_set(n00b_string_t *, body));
                return true;
            }
            // Not followed by `{`: fall through and emit "rewrite"
            // as a normal NAME (so it can still appear as a rule
            // name like `<rewrite>` or a literal identifier).
        }

        n00b_scan_emit(s, .tid = BNF_TOK_NAME,
                       .contents = n00b_option_set(n00b_string_t *, val));
        return true;
    }

    // Single-character tokens.
    n00b_scan_mark(s);
    n00b_scan_advance(s);

    switch (ch) {
    case '?': n00b_scan_emit(s, .tid = BNF_TOK_QUESTION); return true;
    case '*': n00b_scan_emit(s, .tid = BNF_TOK_STAR);     return true;
    case '+': n00b_scan_emit(s, .tid = BNF_TOK_PLUS_OP);  return true;
    case '(': n00b_scan_emit(s, .tid = BNF_TOK_LPAREN);   return true;
    case ')': n00b_scan_emit(s, .tid = BNF_TOK_RPAREN);   return true;
    case '@': n00b_scan_emit(s, .tid = BNF_TOK_AT);       return true;
    case ',': n00b_scan_emit(s, .tid = BNF_TOK_COMMA);    return true;
    default:  break;
    }

    // $N (child reference, digits) | $name: (capture declaration)
    if (ch == '$') {
        n00b_codepoint_t d = n00b_scan_peek(s, 0);

        if (d >= '0' && d <= '9') {
            n00b_scan_mark(s);

            while (!n00b_scan_at_eof(s)) {
                n00b_codepoint_t c = n00b_scan_peek(s, 0);

                if (c < '0' || c > '9') {
                    break;
                }

                n00b_scan_advance(s);
            }

            n00b_string_t *val = n00b_scan_extract(s);
            n00b_scan_emit(s, .tid = BNF_TOK_DOLLAR,
                           .contents = n00b_option_set(n00b_string_t *, val));
            return true;
        }

        // $name: capture declaration. Requires an identifier-shaped
        // name followed by a colon. If the sequence isn't a valid
        // capture, fall back to treating `$` as an unknown char.
        if ((d >= 'a' && d <= 'z') || (d >= 'A' && d <= 'Z') || d == '_') {
            n00b_scan_mark(s);  // mark start of name (after `$`)

            while (!n00b_scan_at_eof(s)) {
                n00b_codepoint_t c = n00b_scan_peek(s, 0);

                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                      || (c >= '0' && c <= '9') || c == '_')) {
                    break;
                }

                n00b_scan_advance(s);
            }

            n00b_string_t *name_val = n00b_scan_extract(s);

            // Require the immediately-following `:` to commit.
            if (!n00b_scan_at_eof(s) && n00b_scan_peek(s, 0) == ':') {
                n00b_scan_advance(s);  // consume `:`
                n00b_scan_emit(
                    s,
                    .tid      = BNF_TOK_CAPTURE_DECL,
                    .contents = n00b_option_set(n00b_string_t *, name_val));
                return true;
            }

            // Not a capture decl after all. The leading `$` is gone
            // and so are the bytes of `name_val`; emit a NAME token
            // for the consumed identifier so the parser sees
            // something coherent. (This is a permissive fallback;
            // real BNF should not contain `$identifier` outside the
            // capture or annotation forms.)
            n00b_scan_emit(
                s,
                .tid      = BNF_TOK_NAME,
                .contents = n00b_option_set(n00b_string_t *, name_val));
            return true;
        }
    }

    // Rewrite blocks open with the contextual keyword `rewrite` followed
    // by `{=*[level]= ... =[level]*=}` (handled in the identifier branch
    // above). A bare `{` in BNF text is not a rewrite block.

    // Unknown character — already advanced, just skip.
    return true;
}

// ============================================================================
// Helper: extract n00b_string_t from token value
// ============================================================================

static n00b_string_t *
tok_str(n00b_token_info_t *tok)
{
    if (!tok || !n00b_option_is_set(tok->value)) {
        return NULL;
    }

    return n00b_option_get(tok->value);
}

static n00b_string_t *
tok_str_or(n00b_token_info_t *tok, n00b_string_t *fallback)
{
    n00b_string_t *s = tok_str(tok);

    if (s) {
        return s;
    }

    return fallback;
}

// Compare n00b_string_t against an n00b_string_t (internal dispatch helper).
static inline bool
str_eq_lit(n00b_string_t *s, n00b_string_t *lit)
{
    return n00b_unicode_str_eq(s, lit);
}

// ============================================================================
// Walk action result types
// ============================================================================

typedef struct {
    int   tag;
    void *data;
} bnf_result_t;

enum {
    BNF_STRING = 1,
    BNF_LIST   = 2,
    BNF_PAIR   = 3,
    BNF_DICT   = 4,
    BNF_GROUP  = 5,
    BNF_ANNOT  = 6,
    BNF_NAME   = 7,
};

typedef void *bnf_ptr_t;
typedef n00b_list_t(bnf_ptr_t) bnf_list_t;

typedef struct {
    bnf_list_t *alternatives;  // list of BNF_LIST results (each is a term list)
    char        quantifier;    // '?', '*', '+'
} bnf_group_info_t;

static inline bnf_list_t *
slist_new(void)
{
    bnf_list_t *l = n00b_alloc(bnf_list_t);
    *l = n00b_list_new_private(bnf_ptr_t);
    return l;
}

static inline void
slist_push(bnf_list_t *l, void *item)
{
    n00b_list_push(*l, (bnf_ptr_t)item);
}

static inline void *
slist_get(bnf_list_t *l, size_t i)
{
    return (l && i < l->len) ? l->data[i] : NULL;
}

static inline void
slist_prepend(bnf_list_t *l, void *item)
{
    n00b_list_push_front(*l, (bnf_ptr_t)item);
}

static inline void
slist_free(bnf_list_t *l)
{
    if (l) {
        n00b_list_free(*l);
        n00b_free(l);
    }
}

static inline bnf_result_t *
bnf_result(int tag, void *data)
{
    bnf_result_t *r = n00b_alloc(bnf_result_t);
    r->tag  = tag;
    r->data = data;
    return r;
}

// ============================================================================
// Walk actions for token-based BNF grammar
// ============================================================================

// term -> LITERAL | LANGLE NAME RANGLE | CLASS | TOKEN_TYPE | TOKEN_LIT | EMPTY_LIT
// Returns BNF_STRING prefixed with type:
//   "L:..." = character literal
//   "N:..." = non-terminal reference
//   "C:..." = character class
//   "T:..." = token type (e.g. %IDENTIFIER -> "T:IDENTIFIER")
//   "K:..." = token literal/keyword (e.g. %"if" -> "K:if")
//   "E:"    = empty string (epsilon)
static void *
bnf_walk_atom(n00b_nt_node_t *pn, void *children, void *thunk)
{
    (void)thunk;
    void **kids = (void **)children;

    if (!kids) {
        char *r = n00b_alloc_array(char, 3);
        r[0] = 'L'; r[1] = ':'; r[2] = '\0';
        return bnf_result(BNF_STRING, r);
    }

    char *result;

    if (pn->rule_index == 0) {
        // term -> LITERAL
        n00b_token_info_t *tok = (n00b_token_info_t *)kids[0];
        n00b_string_t     *val = tok_str_or(tok, r"");
        size_t             len = val->u8_bytes;
        result                 = n00b_alloc_array(char, len + 3);
        result[0]              = 'L';
        result[1]              = ':';
        memcpy(result + 2, val->data, len + 1);
    }
    else if (pn->rule_index == 1) {
        // term -> LANGLE NAME RANGLE
        n00b_token_info_t *tok = (n00b_token_info_t *)kids[1];
        n00b_string_t     *val = tok_str_or(tok, r"");
        size_t             len = val->u8_bytes;
        result                 = n00b_alloc_array(char, len + 3);
        result[0]              = 'N';
        result[1]              = ':';
        memcpy(result + 2, val->data, len + 1);
    }
    else if (pn->rule_index == 2) {
        // term -> CLASS
        n00b_token_info_t *tok = (n00b_token_info_t *)kids[0];
        n00b_string_t     *val = tok_str_or(tok, r"");
        size_t             len = val->u8_bytes;
        result                 = n00b_alloc_array(char, len + 3);
        result[0]              = 'C';
        result[1]              = ':';
        memcpy(result + 2, val->data, len + 1);
    }
    else if (pn->rule_index == 3) {
        // term -> TOKEN_TYPE  (%IDENTIFIER, %STRING, etc.)
        n00b_token_info_t *tok = (n00b_token_info_t *)kids[0];
        n00b_string_t     *val = tok_str_or(tok, r"");
        size_t             len = val->u8_bytes;
        result                 = n00b_alloc_array(char, len + 3);
        result[0]              = 'T';
        result[1]              = ':';
        memcpy(result + 2, val->data, len + 1);
    }
    else if (pn->rule_index == 4) {
        // term -> TOKEN_LIT  (%"if", %"+", etc.)
        // Quoted after % is still as-named (hash-based ID).
        n00b_token_info_t *tok = (n00b_token_info_t *)kids[0];
        n00b_string_t     *val = tok_str_or(tok, r"");
        size_t             len = val->u8_bytes;
        result                 = n00b_alloc_array(char, len + 3);
        result[0]              = 'K';
        result[1]              = ':';
        memcpy(result + 2, val->data, len + 1);
    }
    else if (pn->rule_index == 5) {
        // term -> EMPTY_LIT  ("")
        result = n00b_alloc_array(char, 3);
        result[0] = 'E'; result[1] = ':'; result[2] = '\0';
    }
    else {
        // term -> CAPTURE_DECL LANGLE NAME RANGLE (rule_index 6)
        //   kids[0] = CAPTURE_DECL token (value: capture name without `$` or `:`)
        //   kids[1] = LANGLE
        //   kids[2] = NAME token (NT to reference)
        //   kids[3] = RANGLE
        //
        // Produce "P:capname\0ntname\0" — the resolver in
        // resolve_term_to_matches will split on the embedded NUL,
        // record the capture, and synthesize the NT reference.
        n00b_token_info_t *cap_tok = (n00b_token_info_t *)kids[0];
        n00b_token_info_t *nt_tok  = (n00b_token_info_t *)kids[2];
        n00b_string_t     *cap_s   = tok_str_or(cap_tok, r"?");
        n00b_string_t     *nt_s    = tok_str_or(nt_tok, r"?");
        size_t             clen    = cap_s->u8_bytes;
        size_t             nlen    = nt_s->u8_bytes;

        // Layout: "P:" + cap + "\0" + nt + "\0"
        result    = n00b_alloc_array(char, clen + nlen + 4);
        result[0] = 'P';
        result[1] = ':';
        memcpy(result + 2, cap_s->data, clen);
        result[2 + clen] = '\0';
        memcpy(result + 3 + clen, nt_s->data, nlen);
        result[3 + clen + nlen] = '\0';
    }

    n00b_free(kids);
    return bnf_result(BNF_STRING, result);
}

// item -> atom | atom QUESTION | atom STAR | atom PLUS
//       | LPAREN expression RPAREN | LPAREN expression RPAREN QUESTION
//       | LPAREN expression RPAREN STAR | LPAREN expression RPAREN PLUS
// Returns BNF_STRING (pass-through) or BNF_GROUP for quantified/grouped terms.
static void *
bnf_walk_item(n00b_nt_node_t *pn, void *children, void *thunk)
{
    (void)thunk;
    void **kids = (void **)children;

    if (!kids) {
        char *s = n00b_alloc_array(char, 3);
        s[0] = 'E'; s[1] = ':'; s[2] = '\0';
        return bnf_result(BNF_STRING, s);
    }

    bnf_result_t *result;

    switch (pn->rule_index) {
    case 0:
        // item -> atom  (pass-through)
        result = (bnf_result_t *)kids[0];
        n00b_free(kids);
        return result;

    case 1:  // atom?
    case 2:  // atom*
    case 3: {  // atom+
        char quantifier = (pn->rule_index == 1) ? '?'
                        : (pn->rule_index == 2) ? '*'
                                                : '+';

        // kids[0] = atom result (BNF_STRING), kids[1] = quantifier token
        bnf_group_info_t *gi = n00b_alloc(bnf_group_info_t);
        gi->quantifier       = quantifier;
        gi->alternatives     = slist_new();

        // Single alternative containing the single atom.
        bnf_list_t *terms = slist_new();
        slist_push(terms, kids[0]);
        slist_push(gi->alternatives, bnf_result(BNF_LIST, terms));

        n00b_free(kids);
        return bnf_result(BNF_GROUP, gi);
    }

    case 4: {
        // LPAREN expression RPAREN -> bare group, pass through expression
        // kids[0]=LPAREN, kids[1]=expression result, kids[2]=RPAREN
        bnf_result_t *expr_r = (bnf_result_t *)kids[1];

        // Wrap expression alternatives as a bare group (no quantifier).
        bnf_group_info_t *gi = n00b_alloc(bnf_group_info_t);
        gi->quantifier       = 0;  // no quantifier = bare group
        gi->alternatives     = (bnf_list_t *)expr_r->data;

        n00b_free(expr_r);  // free the wrapper, not the data
        n00b_free(kids);
        return bnf_result(BNF_GROUP, gi);
    }

    case 5:  // (expression)?
    case 6:  // (expression)*
    case 7: {  // (expression)+
        char quantifier = (pn->rule_index == 5) ? '?'
                        : (pn->rule_index == 6) ? '*'
                                                : '+';

        // kids[0]=LPAREN, kids[1]=expression, kids[2]=RPAREN, kids[3]=quantifier
        bnf_result_t *expr_r = (bnf_result_t *)kids[1];

        bnf_group_info_t *gi = n00b_alloc(bnf_group_info_t);
        gi->quantifier       = quantifier;
        gi->alternatives     = (bnf_list_t *)expr_r->data;

        n00b_free(expr_r);
        n00b_free(kids);
        return bnf_result(BNF_GROUP, gi);
    }

    default:
        n00b_free(kids);
        {
            char *es = n00b_alloc_array(char, 3);
            es[0] = 'E'; es[1] = ':'; es[2] = '\0';
            return bnf_result(BNF_STRING, es);
        }
    }
}

// list -> item | list item
// Returns BNF_LIST of item results.
static void *
bnf_walk_list(n00b_nt_node_t *pn, void *children, void *thunk)
{
    (void)thunk;
    void **kids = (void **)children;

    if (!kids) {
        return bnf_result(BNF_LIST, slist_new());
    }

    bnf_list_t *result;

    if (pn->rule_index == 0) {
        // list -> item
        result = slist_new();
        slist_push(result, kids[0]);
    }
    else {
        // list -> list item
        bnf_result_t *list_r = (bnf_result_t *)kids[0];
        result               = list_r ? (bnf_list_t *)list_r->data : slist_new();
        slist_push(result, kids[1]);

        if (list_r) {
            n00b_free(list_r);
        }
    }

    n00b_free(kids);
    return bnf_result(BNF_LIST, result);
}

// expression -> list | expression PIPE list
// Returns BNF_LIST of BNF_LIST (list of alternatives).
static void *
bnf_walk_expression(n00b_nt_node_t *pn, void *children, void *thunk)
{
    (void)thunk;
    void **kids = (void **)children;

    if (!kids) {
        return bnf_result(BNF_LIST, slist_new());
    }

    bnf_list_t *result;

    if (pn->rule_index == 0) {
        // expression -> list
        result = slist_new();
        slist_push(result, kids[0]);
    }
    else {
        // expression -> expression PIPE list
        bnf_result_t *expr_r = (bnf_result_t *)kids[0];
        result               = expr_r ? (bnf_list_t *)expr_r->data : slist_new();
        slist_push(result, kids[2]);

        if (expr_r) {
            n00b_free(expr_r);
        }
    }

    n00b_free(kids);
    return bnf_result(BNF_LIST, result);
}

// ============================================================================
// Annotation walk data
// ============================================================================

typedef struct {
    n00b_annot_kind_t kind;
    n00b_child_ref_t  name_ref;
    n00b_child_ref_t  type_ref;
    n00b_child_ref_t  value_ref;
    n00b_string_t    *scope_tag;
    bool              capture_by_tag;
    n00b_string_t    *type_spec;
    n00b_string_t    *infer_expr;
    n00b_string_t    *adt_kind;
    n00b_string_t    *visibility_spec;
    n00b_string_t    *op_kind;
    n00b_child_ref_t  notrivia_ref;
    n00b_string_t    *sym_kind;
    n00b_child_ref_t  adt_keyword_ref;
    int32_t           penalty_cost;
} bnf_annot_info_t;

// Parse a child-ref from a walk result: DOLLAR token -> by-index, NAME -> by-name
static n00b_child_ref_t
parse_child_ref(void *result)
{
    if (!result) {
        return (n00b_child_ref_t){.kind = N00B_ROLE_BY_INDEX, .index = -1};
    }

    n00b_token_info_t *tok = (n00b_token_info_t *)result;

    if (tok->tid == BNF_TOK_DOLLAR) {
        n00b_string_t *val = tok_str(tok);
        int32_t        ix  = val ? (int32_t)atoi(val->data) : -1;
        return (n00b_child_ref_t){.kind = N00B_ROLE_BY_INDEX, .index = ix};
    }

    // NAME token -> by NT name
    if (tok->tid == BNF_TOK_NAME) {
        n00b_string_t *val = tok_str(tok);

        if (val) {
            return (n00b_child_ref_t){.kind = N00B_ROLE_BY_NAME, .name = val};
        }
    }

    return (n00b_child_ref_t){.kind = N00B_ROLE_BY_INDEX, .index = -1};
}

// arg -> LITERAL | DOLLAR | NAME
// Returns the raw token (not wrapped in bnf_result_t).
static void *
bnf_walk_annot_arg(n00b_nt_node_t *pn, void *children, void *thunk)
{
    (void)pn;
    (void)thunk;
    void **kids = (void **)children;

    if (!kids) {
        return NULL;
    }

    // All three rules return a single token -- pass it through.
    void *tok = kids[0];
    n00b_free(kids);
    return tok;
}

// arg-list -> arg | arg-list COMMA arg
// Returns BNF_LIST of arg results (raw tokens).
static void *
bnf_walk_arg_list(n00b_nt_node_t *pn, void *children, void *thunk)
{
    (void)thunk;
    void **kids = (void **)children;

    if (!kids) {
        return bnf_result(BNF_LIST, slist_new());
    }

    bnf_list_t *result;

    if (pn->rule_index == 0) {
        // arg-list -> arg
        result = slist_new();
        slist_push(result, kids[0]);
    }
    else {
        // arg-list -> arg-list COMMA arg
        bnf_result_t *list_r = (bnf_result_t *)kids[0];
        result = list_r ? (bnf_list_t *)list_r->data : slist_new();
        slist_push(result, kids[2]);

        if (list_r) {
            n00b_free(list_r);
        }
    }

    n00b_free(kids);
    return bnf_result(BNF_LIST, result);
}

// annotation -> AT NAME LPAREN arg-list RPAREN  (rule 0)
//            | AT NAME                          (rule 1)
// Returns BNF_ANNOT with bnf_annot_info_t
static void *
bnf_walk_annotation(n00b_nt_node_t *pn, void *children, void *thunk)
{
    (void)thunk;
    void **kids = (void **)children;

    if (!kids) {
        return NULL;
    }

    // rule 0: kids[0]=AT, kids[1]=NAME, kids[2]=LPAREN, kids[3]=arg-list, kids[4]=RPAREN
    // rule 1: kids[0]=AT, kids[1]=NAME
    n00b_token_info_t *name_tok = (n00b_token_info_t *)kids[1];
    bnf_result_t   *args_r = NULL;
    bnf_list_t     *args   = NULL;

    if (pn->rule_index == 0) {
        args_r = (bnf_result_t *)kids[3];
        args   = args_r ? (bnf_list_t *)args_r->data : NULL;
    }

    bnf_annot_info_t *info = n00b_alloc(bnf_annot_info_t);
    info->name_ref  = (n00b_child_ref_t){.kind = N00B_ROLE_BY_INDEX, .index = -1};
    info->type_ref  = (n00b_child_ref_t){.kind = N00B_ROLE_BY_INDEX, .index = -1};
    info->value_ref = (n00b_child_ref_t){.kind = N00B_ROLE_BY_INDEX, .index = -1};

    n00b_string_t *annot_str = tok_str(name_tok);

    if (str_eq_lit(annot_str, r"scope")) {
        info->kind = N00B_ANNOT_SCOPE_OPEN;

        // arg 0 = tag (LITERAL), arg 1 = name-ref (optional)
        if (args && args->len >= 1) {
            n00b_token_info_t *tag_tok = (n00b_token_info_t *)slist_get(args, 0);
            info->scope_tag = tok_str(tag_tok);
        }

        if (args && args->len >= 2) {
            info->name_ref = parse_child_ref(slist_get(args, 1));
        }
    }
    else if (str_eq_lit(annot_str, r"declares")) {
        info->kind = N00B_ANNOT_DECLARES;

        // @declares($name)
        // @declares($name, $type)
        // @declares($name, "kind")           — sym_kind without type
        // @declares($name, $type, "kind")    — sym_kind with type
        info->type_ref = N00B_CHILD_NONE;

        if (args && args->len >= 1) {
            info->name_ref = parse_child_ref(slist_get(args, 0));
        }

        if (args && args->len == 2) {
            n00b_token_info_t *arg1 = (n00b_token_info_t *)slist_get(args, 1);

            if (arg1 && arg1->tid == BNF_TOK_LITERAL) {
                info->sym_kind = tok_str(arg1);
            }
            else {
                info->type_ref = parse_child_ref(slist_get(args, 1));
            }
        }
        else if (args && args->len >= 3) {
            info->type_ref = parse_child_ref(slist_get(args, 1));
            n00b_token_info_t *arg2 = (n00b_token_info_t *)slist_get(args, 2);

            if (arg2 && arg2->tid == BNF_TOK_LITERAL) {
                info->sym_kind = tok_str(arg2);
            }
        }
    }
    else if (str_eq_lit(annot_str, r"type")) {
        if (args && args->len >= 2) {
            // 2-arg form: @type($n, "type_spec")
            info->kind     = N00B_ANNOT_TYPE;
            info->name_ref = parse_child_ref(slist_get(args, 0));

            n00b_token_info_t *spec_tok =
                (n00b_token_info_t *)slist_get(args, 1);
            info->type_spec = tok_str(spec_tok);
        }
        else {
            // 1-arg form: @type($n) -- backward-compatible TYPE_DECL
            info->kind = N00B_ANNOT_TYPE_DECL;

            if (args && args->len >= 1) {
                info->name_ref = parse_child_ref(slist_get(args, 0));
            }
        }
    }
    else if (str_eq_lit(annot_str, r"assigns")) {
        info->kind = N00B_ANNOT_ASSIGNS;

        if (args && args->len >= 1) {
            info->name_ref = parse_child_ref(slist_get(args, 0));
        }

        if (args && args->len >= 2) {
            info->value_ref = parse_child_ref(slist_get(args, 1));
        }
    }
    else if (str_eq_lit(annot_str, r"branch")) {
        info->kind = N00B_ANNOT_BRANCH;

        if (args && args->len >= 1) {
            info->name_ref = parse_child_ref(slist_get(args, 0));
        }

        if (args && args->len >= 2) {
            info->type_ref = parse_child_ref(slist_get(args, 1));
        }

        if (args && args->len >= 3) {
            info->value_ref = parse_child_ref(slist_get(args, 2));
        }
    }
    else if (str_eq_lit(annot_str, r"switch")) {
        info->kind = N00B_ANNOT_SWITCH;

        if (args && args->len >= 1) {
            info->name_ref = parse_child_ref(slist_get(args, 0));
        }

        if (args && args->len >= 2) {
            info->type_ref = parse_child_ref(slist_get(args, 1));
        }
    }
    else if (str_eq_lit(annot_str, r"loop")) {
        info->kind = N00B_ANNOT_LOOP;

        if (args && args->len >= 1) {
            info->name_ref = parse_child_ref(slist_get(args, 0));
        }

        if (args && args->len >= 2) {
            info->type_ref = parse_child_ref(slist_get(args, 1));
        }
    }
    else if (str_eq_lit(annot_str, r"jump")) {
        info->kind = N00B_ANNOT_JUMP;

        if (args && args->len >= 1) {
            n00b_token_info_t *tag_tok = (n00b_token_info_t *)slist_get(args, 0);
            info->scope_tag = tok_str(tag_tok);
        }
    }
    else if (str_eq_lit(annot_str, r"capture")) {
        info->kind = N00B_ANNOT_CAPTURE;

        // arg 0: tag (LITERAL string)
        if (args && args->len >= 1) {
            n00b_token_info_t *tag_tok = (n00b_token_info_t *)slist_get(args, 0);
            info->scope_tag = tok_str(tag_tok);
        }

        // arg 1: optional "dynamic" keyword (NAME token)
        if (args && args->len >= 2) {
            n00b_token_info_t *mode_tok = (n00b_token_info_t *)slist_get(args, 1);
            n00b_string_t     *mode_val = tok_str(mode_tok);

            if (mode_val && str_eq_lit(mode_val, r"dynamic")) {
                info->capture_by_tag = true;
            }
        }
    }
    // Formatting annotations
    else if (str_eq_lit(annot_str, r"indent")) {
        info->kind = N00B_ANNOT_INDENT;
    }
    else if (str_eq_lit(annot_str, r"group")) {
        info->kind = N00B_ANNOT_GROUP;
    }
    else if (str_eq_lit(annot_str, r"concat")) {
        info->kind = N00B_ANNOT_CONCAT;
    }
    else if (str_eq_lit(annot_str, r"blankline")) {
        info->kind = N00B_ANNOT_BLANKLINE;
    }
    else if (str_eq_lit(annot_str, r"softline")) {
        info->kind = N00B_ANNOT_SOFTLINE;

        if (args && args->len >= 1) {
            info->name_ref = parse_child_ref(slist_get(args, 0));
        }
    }
    else if (str_eq_lit(annot_str, r"hardline")) {
        info->kind = N00B_ANNOT_HARDLINE;

        if (args && args->len >= 1) {
            info->name_ref = parse_child_ref(slist_get(args, 0));
        }
    }
    else if (str_eq_lit(annot_str, r"newline")) {
        info->kind = N00B_ANNOT_NEWLINE;

        if (args && args->len >= 1) {
            info->name_ref = parse_child_ref(slist_get(args, 0));
        }
    }
    else if (str_eq_lit(annot_str, r"space")) {
        info->kind = N00B_ANNOT_SPACE;

        if (args && args->len >= 1) {
            info->name_ref = parse_child_ref(slist_get(args, 0));
        }
    }
    else if (str_eq_lit(annot_str, r"nospace")) {
        info->kind = N00B_ANNOT_NOSPACE;

        if (args && args->len >= 1) {
            info->name_ref = parse_child_ref(slist_get(args, 0));
        }
    }
    else if (str_eq_lit(annot_str, r"align")) {
        info->kind = N00B_ANNOT_ALIGN;

        if (args && args->len >= 1) {
            info->name_ref = parse_child_ref(slist_get(args, 0));
        }
    }
    else if (str_eq_lit(annot_str, r"tokenizer")) {
        info->kind = N00B_ANNOT_TOKENIZER;

        // arg 0: tokenizer name (LITERAL string, e.g. "c")
        if (args && args->len >= 1) {
            n00b_token_info_t *name_tok2 = (n00b_token_info_t *)slist_get(args, 0);
            info->scope_tag = tok_str(name_tok2);
        }
    }
    else if (str_eq_lit(annot_str, r"infer")) {
        info->kind = N00B_ANNOT_INFER;

        // arg 0: constraint expression string (LITERAL)
        if (args && args->len >= 1) {
            n00b_token_info_t *expr_tok = (n00b_token_info_t *)slist_get(args, 0);
            info->infer_expr = tok_str(expr_tok);
        }
    }
    else if (str_eq_lit(annot_str, r"adt")) {
        info->kind = N00B_ANNOT_ADT;

        // arg 0: LITERAL -> adt_kind ("class", "struct", "enum", "interface")
        // arg 1: child_ref -> name_ref
        // arg 2: optional LITERAL -> scope_tag (defaults to adt_kind)
        // arg 3: optional child_ref -> adt_keyword_ref (keyword child)
        if (args && args->len >= 1) {
            n00b_token_info_t *kind_tok = (n00b_token_info_t *)slist_get(args, 0);
            info->adt_kind = tok_str(kind_tok);
        }

        if (args && args->len >= 2) {
            info->name_ref = parse_child_ref(slist_get(args, 1));
        }

        if (args && args->len >= 3) {
            n00b_token_info_t *tag_tok = (n00b_token_info_t *)slist_get(args, 2);
            info->scope_tag = tok_str(tag_tok);
        }

        if (args && args->len >= 4) {
            info->adt_keyword_ref = parse_child_ref(slist_get(args, 3));
        }
    }
    else if (str_eq_lit(annot_str, r"field")) {
        info->kind = N00B_ANNOT_FIELD;

        // arg 0: child_ref -> name_ref
        // arg 1: child_ref -> type_ref
        if (args && args->len >= 1) {
            info->name_ref = parse_child_ref(slist_get(args, 0));
        }

        if (args && args->len >= 2) {
            info->type_ref = parse_child_ref(slist_get(args, 1));
        }
    }
    else if (str_eq_lit(annot_str, r"method")) {
        info->kind = N00B_ANNOT_METHOD;

        // arg 0: child_ref -> name_ref
        // arg 1: child_ref -> type_ref (optional)
        if (args && args->len >= 1) {
            info->name_ref = parse_child_ref(slist_get(args, 0));
        }

        if (args && args->len >= 2) {
            info->type_ref = parse_child_ref(slist_get(args, 1));
        }
    }
    else if (str_eq_lit(annot_str, r"inherits")) {
        info->kind = N00B_ANNOT_INHERITS;

        // arg 0: child_ref -> name_ref (parent type name)
        if (args && args->len >= 1) {
            info->name_ref = parse_child_ref(slist_get(args, 0));
        }
    }
    else if (str_eq_lit(annot_str, r"implements")) {
        info->kind = N00B_ANNOT_IMPLEMENTS;

        // arg 0: child_ref -> name_ref (interface name)
        if (args && args->len >= 1) {
            info->name_ref = parse_child_ref(slist_get(args, 0));
        }
    }
    else if (str_eq_lit(annot_str, r"visibility")) {
        info->kind = N00B_ANNOT_VISIBILITY;

        // arg 0: LITERAL -> visibility_spec ("public", "private", "protected")
        if (args && args->len >= 1) {
            n00b_token_info_t *vis_tok = (n00b_token_info_t *)slist_get(args, 0);
            info->visibility_spec = tok_str(vis_tok);
        }
    }
    else if (str_eq_lit(annot_str, r"static")) {
        info->kind = N00B_ANNOT_STATIC;
    }
    else if (str_eq_lit(annot_str, r"abstract")) {
        info->kind = N00B_ANNOT_ABSTRACT;
    }
    else if (str_eq_lit(annot_str, r"operator")) {
        // @operator("+")
        info->kind = N00B_ANNOT_OPERATOR;
        if (args && args->len >= 1) {
            n00b_token_info_t *op_tok = (n00b_token_info_t *)slist_get(args, 0);
            info->op_kind = tok_str(op_tok);
        }
    }
    else if (str_eq_lit(annot_str, r"literal")) {
        // @literal("int")           — base type only
        // @literal("int", $2)       — base type + type modifier child ref
        info->kind = N00B_ANNOT_LITERAL;
        if (args && args->len >= 1) {
            n00b_token_info_t *lit_tok = (n00b_token_info_t *)slist_get(args, 0);
            info->op_kind = tok_str(lit_tok);
        }

        if (args && args->len >= 2) {
            info->type_ref = parse_child_ref(slist_get(args, 1));
        }
    }
    else if (str_eq_lit(annot_str, r"call")) {
        // @call($0, $2)
        info->kind = N00B_ANNOT_CALL;
        if (args && args->len >= 1) {
            info->name_ref = parse_child_ref(slist_get(args, 0));
        }
        if (args && args->len >= 2) {
            info->type_ref = parse_child_ref(slist_get(args, 1));
        }
    }
    else if (str_eq_lit(annot_str, r"varref")) {
        // @varref($0)
        info->kind = N00B_ANNOT_VARREF;
        if (args && args->len >= 1) {
            info->name_ref = parse_child_ref(slist_get(args, 0));
        }
    }
    else if (str_eq_lit(annot_str, r"penalty")) {
        // @penalty(N) -- applied to rule, not NT
        info->kind = N00B_ANNOT_PENALTY;

        if (args && args->len >= 1) {
            n00b_token_info_t *cost_tok = (n00b_token_info_t *)slist_get(args, 0);
            n00b_string_t     *cost_val = tok_str(cost_tok);

            if (cost_val) {
                info->penalty_cost = (int32_t)strtol(cost_val->data, NULL, 10);
            }
        }

        if (info->penalty_cost <= 0) {
            info->penalty_cost = 1;
        }
    }
    else if (str_eq_lit(annot_str, r"notrivia")) {
        // @notrivia($1) — child at given index must have no leading trivia.
        info->kind = N00B_ANNOT_NOTRIVIA;

        if (args && args->len >= 1) {
            info->notrivia_ref = parse_child_ref(slist_get(args, 0));
        }
    }
    else if (str_eq_lit(annot_str, r"exposes")) {
        info->kind = N00B_ANNOT_EXPOSES;
    }
    else if (str_eq_lit(annot_str, r"record")) {
        info->kind = N00B_ANNOT_RECORD;

        if (args && args->len >= 1) {
            info->name_ref = parse_child_ref(slist_get(args, 0));
        }
    }

    if (args_r) {
        // Free the wrapper but not the token data inside
        slist_free(args);
        n00b_free(args_r);
    }

    n00b_free(kids);
    return bnf_result(BNF_ANNOT, info);
}

// annotations -> "" | annotation annotations
// Returns BNF_LIST of BNF_ANNOT results.
static void *
bnf_walk_annotations(n00b_nt_node_t *pn, void *children, void *thunk)
{
    (void)thunk;
    void **kids = (void **)children;

    if (!kids) {
        return bnf_result(BNF_LIST, slist_new());
    }

    bnf_list_t *result;

    if (pn->rule_index == 0) {
        // annotations -> "" (empty)
        result = slist_new();
    }
    else {
        // annotations -> annotation annotations
        bnf_result_t *rest_r = (bnf_result_t *)kids[1];
        result = rest_r ? (bnf_list_t *)rest_r->data : slist_new();
        slist_prepend(result, kids[0]);

        if (rest_r) {
            n00b_free(rest_r);
        }
    }

    n00b_free(kids);
    return bnf_result(BNF_LIST, result);
}

// rule -> LANGLE NAME RANGLE annotations ASSIGN expression NEWLINE
//                                                           [REWRITE_BLOCK NEWLINE]
// Returns BNF_PAIR [name_string, expression_result, annotations_list, rewrite_body_string_or_null].
static void *
bnf_walk_rule(n00b_nt_node_t *pn, void *children, void *thunk)
{
    (void)thunk;
    void **kids = (void **)children;

    if (!kids) {
        return NULL;
    }

    // All rule variants share this structure:
    //   < NAME > [NEWLINE] annotations ::= [NEWLINE] expression NEWLINE
    //                                              [REWRITE_BLOCK NEWLINE]
    //
    // The two existing booleans encode optional NEWLINEs after '>' and
    // after '::='. We add a third bit (rule_index >= 4) for the
    // optional trailing REWRITE_BLOCK form.
    //
    // Rule indices are packed:
    //   bit 0 = NL after ::=
    //   bit 1 = NL after >
    //   bit 2 = has REWRITE_BLOCK
    // The grammar adds rules in two layers (without, then with the
    // trailing block); see build_bnf_grammar.

    bool nl_after_rangle = (pn->rule_index & 2) != 0;
    bool nl_after_assign = (pn->rule_index & 1) != 0;
    bool has_rewrite     = (pn->rule_index & 4) != 0;

    int annots_idx = 3 + nl_after_rangle;
    int expr_idx   = annots_idx + 2 + nl_after_assign;

    n00b_token_info_t *name_tok = (n00b_token_info_t *)kids[1];
    bnf_result_t      *annots_r = (bnf_result_t *)kids[annots_idx];
    bnf_result_t      *expr_r   = (bnf_result_t *)kids[expr_idx];

    n00b_string_t *name_s = tok_str_or(name_tok, r"?");

    // Extract the rewrite-block body (if any). The block token sits at
    // expr_idx + 2 (skipping NEWLINE after expression).
    n00b_string_t *rewrite_body = nullptr;
    if (has_rewrite) {
        n00b_token_info_t *body_tok = (n00b_token_info_t *)kids[expr_idx + 2];
        rewrite_body                = tok_str(body_tok);
    }

    bnf_list_t *triple = slist_new();
    slist_push(triple, bnf_result(BNF_NAME, name_s));
    slist_push(triple, expr_r);
    slist_push(triple, annots_r);
    if (rewrite_body) {
        slist_push(triple, bnf_result(BNF_NAME, rewrite_body));
    }
    else {
        slist_push(triple, nullptr);
    }

    n00b_free(kids);
    return bnf_result(BNF_PAIR, triple);
}

// syntax -> rule | syntax rule | syntax NEWLINE | NEWLINE
//        | syntax annotation NEWLINE | annotation NEWLINE
// Returns BNF_DICT (list of pairs).
static void *
bnf_walk_syntax(n00b_nt_node_t *pn, void *children, void *thunk)
{
    (void)thunk;
    void **kids = (void **)children;

    if (!kids) {
        return bnf_result(BNF_DICT, slist_new());
    }

    bnf_list_t *result;

    if (pn->rule_index == 0) {
        // syntax -> rule
        result = slist_new();

        if (kids[0]) {
            slist_push(result, kids[0]);
        }
    }
    else if (pn->rule_index == 1) {
        // syntax -> syntax rule
        bnf_result_t *syntax_r = (bnf_result_t *)kids[0];
        result = syntax_r ? (bnf_list_t *)syntax_r->data : slist_new();

        if (kids[1]) {
            slist_push(result, kids[1]);
        }

        if (syntax_r) {
            n00b_free(syntax_r);
        }
    }
    else if (pn->rule_index == 2) {
        // syntax -> syntax NEWLINE
        bnf_result_t *syntax_r = (bnf_result_t *)kids[0];
        result = syntax_r ? (bnf_list_t *)syntax_r->data : slist_new();

        if (syntax_r) {
            n00b_free(syntax_r);
        }
    }
    else if (pn->rule_index == 3) {
        // syntax -> NEWLINE
        result = slist_new();
    }
    else if (pn->rule_index == 4) {
        // syntax -> syntax annotation NEWLINE
        bnf_result_t *syntax_r = (bnf_result_t *)kids[0];
        result = syntax_r ? (bnf_list_t *)syntax_r->data : slist_new();

        if (syntax_r) {
            n00b_free(syntax_r);
        }

        // Wrap the grammar-level annotation as a triple with empty name.
        if (kids[1]) {
            bnf_list_t *annot_list = slist_new();
            slist_push(annot_list, kids[1]);
            bnf_result_t *annots_r = bnf_result(BNF_LIST, annot_list);

            bnf_list_t *triple = slist_new();
            {
                n00b_string_t *empty = n00b_string_empty();
                slist_push(triple, bnf_result(BNF_NAME, empty));
            }
            slist_push(triple, NULL);  // no expression
            slist_push(triple, annots_r);
            slist_push(result, bnf_result(BNF_PAIR, triple));
        }
    }
    else {
        // syntax -> annotation NEWLINE (rule 5)
        result = slist_new();

        if (kids[0]) {
            bnf_list_t *annot_list = slist_new();
            slist_push(annot_list, kids[0]);
            bnf_result_t *annots_r = bnf_result(BNF_LIST, annot_list);

            bnf_list_t *triple = slist_new();
            {
                n00b_string_t *empty = n00b_string_empty();
                slist_push(triple, bnf_result(BNF_NAME, empty));
            }
            slist_push(triple, NULL);
            slist_push(triple, annots_r);
            slist_push(result, bnf_result(BNF_PAIR, triple));
        }
    }

    n00b_free(kids);
    return bnf_result(BNF_DICT, result);
}

// ============================================================================
// Build the BNF meta-grammar (token-level)
// ============================================================================

static n00b_grammar_t *
build_bnf_grammar(void)
{
    // The BNF meta-grammar is always parsed PWZ-only (see n00b_parse below);
    // instantiating PWZ_ONLY also forces its error-recovery rules off.
    n00b_grammar_t *g = n00b_grammar_new(.parse_mode = N00B_PARSE_MODE_PWZ_ONLY);

    // Register token types.
    int64_t LANGLE     = BNF_TOK_LANGLE;
    int64_t RANGLE     = BNF_TOK_RANGLE;
    int64_t ASSIGN     = BNF_TOK_ASSIGN;
    int64_t PIPE       = BNF_TOK_PIPE;
    int64_t NEWLINE    = BNF_TOK_NEWLINE;
    int64_t NAME       = BNF_TOK_NAME;
    int64_t LITERAL    = BNF_TOK_LITERAL;
    int64_t CLASS      = BNF_TOK_CLASS;
    int64_t TOKEN_TYPE = BNF_TOK_TOKEN_TYPE;
    int64_t TOKEN_LIT  = BNF_TOK_TOKEN_LIT;
    int64_t EMPTY_LIT  = BNF_TOK_EMPTY_LIT;
    int64_t QUESTION   = BNF_TOK_QUESTION;
    int64_t STAR       = BNF_TOK_STAR;
    int64_t PLUS_OP    = BNF_TOK_PLUS_OP;
    int64_t LPAREN     = BNF_TOK_LPAREN;
    int64_t RPAREN     = BNF_TOK_RPAREN;
    int64_t AT         = BNF_TOK_AT;
    int64_t DOLLAR     = BNF_TOK_DOLLAR;
    int64_t COMMA      = BNF_TOK_COMMA;

    // Register a readable name for the newline token (non-visible).
    n00b_string_t *nl_name = r"newline";
    n00b_dict_put(g->terminal_by_id, NEWLINE, nl_name);

    // Create all non-terminals.
    n00b_string_t *s_syntax      = r"syntax";
    n00b_string_t *s_rule        = r"rule";
    n00b_string_t *s_expression  = r"expression";
    n00b_string_t *s_list        = r"list";
    n00b_string_t *s_item        = r"item";
    n00b_string_t *s_atom        = r"atom";
    n00b_string_t *s_annotations = r"annotations";
    n00b_string_t *s_annotation  = r"annotation";
    n00b_string_t *s_arg_list    = r"arg-list";
    n00b_string_t *s_annot_arg   = r"annot-arg";

    n00b_nonterm(g, s_syntax);
    n00b_nonterm(g, s_rule);
    n00b_nonterm(g, s_expression);
    n00b_nonterm(g, s_list);
    n00b_nonterm(g, s_item);
    n00b_nonterm(g, s_atom);
    n00b_nonterm(g, s_annotations);
    n00b_nonterm(g, s_annotation);
    n00b_nonterm(g, s_arg_list);
    n00b_nonterm(g, s_annot_arg);

    // Capture IDs — never hold n00b_nonterm_t * across grammar mutations,
    // because n00b_add_rule can create error NTs which reallocate nt_list.
    n00b_nt_id_t syntax_id      = n00b_nonterm_id(n00b_nonterm(g, s_syntax));
    n00b_nt_id_t rule_id        = n00b_nonterm_id(n00b_nonterm(g, s_rule));
    n00b_nt_id_t expression_id  = n00b_nonterm_id(n00b_nonterm(g, s_expression));
    n00b_nt_id_t list_id        = n00b_nonterm_id(n00b_nonterm(g, s_list));
    n00b_nt_id_t item_id        = n00b_nonterm_id(n00b_nonterm(g, s_item));
    n00b_nt_id_t atom_id        = n00b_nonterm_id(n00b_nonterm(g, s_atom));
    n00b_nt_id_t annotations_id = n00b_nonterm_id(n00b_nonterm(g, s_annotations));
    n00b_nt_id_t annotation_id  = n00b_nonterm_id(n00b_nonterm(g, s_annotation));
    n00b_nt_id_t arg_list_id    = n00b_nonterm_id(n00b_nonterm(g, s_arg_list));
    n00b_nt_id_t annot_arg_id   = n00b_nonterm_id(n00b_nonterm(g, s_annot_arg));

#define NT(id) (n00b_match_t){.kind = N00B_MATCH_NT, .nt_id = (id)}

    n00b_grammar_set_start_id(g, syntax_id);

    // syntax -> rule | syntax rule | syntax NEWLINE | NEWLINE
    //        | syntax annotation NEWLINE | annotation NEWLINE
    n00b_add_rule_v(g, syntax_id, 1,
                     (n00b_match_t[]){NT(rule_id)});
    n00b_add_rule_v(g, syntax_id, 2,
                     (n00b_match_t[]){NT(syntax_id), NT(rule_id)});
    n00b_add_rule_v(g, syntax_id, 2,
                     (n00b_match_t[]){NT(syntax_id), N00B_TERMINAL(NEWLINE)});
    n00b_add_rule_v(g, syntax_id, 1,
                     (n00b_match_t[]){N00B_TERMINAL(NEWLINE)});
    n00b_add_rule_v(g, syntax_id, 3,
                     (n00b_match_t[]){NT(syntax_id), NT(annotation_id),
                                      N00B_TERMINAL(NEWLINE)});
    n00b_add_rule_v(g, syntax_id, 2,
                     (n00b_match_t[]){NT(annotation_id), N00B_TERMINAL(NEWLINE)});

    int64_t CAPTURE_DECL  = BNF_TOK_CAPTURE_DECL;
    int64_t REWRITE_BLOCK = BNF_TOK_REWRITE_BLOCK;

    // rule -> LANGLE NAME RANGLE annotations ASSIGN expression NEWLINE
    // Optional NEWLINE allowed after RANGLE (before annotations) and after ASSIGN.
    //
    // rule_index encoding (matches bnf_walk_rule):
    //   bit 0 = NL after ::=
    //   bit 1 = NL after >
    //   bit 2 = trailing REWRITE_BLOCK + NEWLINE present
    //
    // For each of the 4 base shapes we add a no-rewrite variant
    // (indices 0..3) followed by the rewrite-bearing variant
    // (indices 4..7) — same RHS plus REWRITE_BLOCK NEWLINE on the end.

    // Index 0: ... ASSIGN expression NEWLINE
    n00b_add_rule_v(g, rule_id, 7,
                     (n00b_match_t[]){N00B_TERMINAL(LANGLE), N00B_TERMINAL(NAME),
                                      N00B_TERMINAL(RANGLE), NT(annotations_id),
                                      N00B_TERMINAL(ASSIGN),
                                      NT(expression_id), N00B_TERMINAL(NEWLINE)});
    // Index 1: ... ASSIGN NEWLINE expression NEWLINE
    n00b_add_rule_v(g, rule_id, 8,
                     (n00b_match_t[]){N00B_TERMINAL(LANGLE), N00B_TERMINAL(NAME),
                                      N00B_TERMINAL(RANGLE), NT(annotations_id),
                                      N00B_TERMINAL(ASSIGN), N00B_TERMINAL(NEWLINE),
                                      NT(expression_id), N00B_TERMINAL(NEWLINE)});
    // Index 2: ... RANGLE NEWLINE annotations ASSIGN expression NEWLINE
    n00b_add_rule_v(g, rule_id, 8,
                     (n00b_match_t[]){N00B_TERMINAL(LANGLE), N00B_TERMINAL(NAME),
                                      N00B_TERMINAL(RANGLE), N00B_TERMINAL(NEWLINE),
                                      NT(annotations_id),
                                      N00B_TERMINAL(ASSIGN),
                                      NT(expression_id), N00B_TERMINAL(NEWLINE)});
    // Index 3: ... RANGLE NEWLINE annotations ASSIGN NEWLINE expression NEWLINE
    n00b_add_rule_v(g, rule_id, 9,
                     (n00b_match_t[]){N00B_TERMINAL(LANGLE), N00B_TERMINAL(NAME),
                                      N00B_TERMINAL(RANGLE), N00B_TERMINAL(NEWLINE),
                                      NT(annotations_id),
                                      N00B_TERMINAL(ASSIGN), N00B_TERMINAL(NEWLINE),
                                      NT(expression_id), N00B_TERMINAL(NEWLINE)});

    // Indices 4..7 — same as 0..3 with trailing REWRITE_BLOCK NEWLINE.
    n00b_add_rule_v(g, rule_id, 9,
                     (n00b_match_t[]){N00B_TERMINAL(LANGLE), N00B_TERMINAL(NAME),
                                      N00B_TERMINAL(RANGLE), NT(annotations_id),
                                      N00B_TERMINAL(ASSIGN),
                                      NT(expression_id), N00B_TERMINAL(NEWLINE),
                                      N00B_TERMINAL(REWRITE_BLOCK),
                                      N00B_TERMINAL(NEWLINE)});
    n00b_add_rule_v(g, rule_id, 10,
                     (n00b_match_t[]){N00B_TERMINAL(LANGLE), N00B_TERMINAL(NAME),
                                      N00B_TERMINAL(RANGLE), NT(annotations_id),
                                      N00B_TERMINAL(ASSIGN), N00B_TERMINAL(NEWLINE),
                                      NT(expression_id), N00B_TERMINAL(NEWLINE),
                                      N00B_TERMINAL(REWRITE_BLOCK),
                                      N00B_TERMINAL(NEWLINE)});
    n00b_add_rule_v(g, rule_id, 10,
                     (n00b_match_t[]){N00B_TERMINAL(LANGLE), N00B_TERMINAL(NAME),
                                      N00B_TERMINAL(RANGLE), N00B_TERMINAL(NEWLINE),
                                      NT(annotations_id),
                                      N00B_TERMINAL(ASSIGN),
                                      NT(expression_id), N00B_TERMINAL(NEWLINE),
                                      N00B_TERMINAL(REWRITE_BLOCK),
                                      N00B_TERMINAL(NEWLINE)});
    n00b_add_rule_v(g, rule_id, 11,
                     (n00b_match_t[]){N00B_TERMINAL(LANGLE), N00B_TERMINAL(NAME),
                                      N00B_TERMINAL(RANGLE), N00B_TERMINAL(NEWLINE),
                                      NT(annotations_id),
                                      N00B_TERMINAL(ASSIGN), N00B_TERMINAL(NEWLINE),
                                      NT(expression_id), N00B_TERMINAL(NEWLINE),
                                      N00B_TERMINAL(REWRITE_BLOCK),
                                      N00B_TERMINAL(NEWLINE)});

    // expression -> list | expression PIPE list
    n00b_add_rule_v(g, expression_id, 1,
                     (n00b_match_t[]){NT(list_id)});
    n00b_add_rule_v(g, expression_id, 3,
                     (n00b_match_t[]){NT(expression_id), N00B_TERMINAL(PIPE),
                                      NT(list_id)});

    // list -> item | list item
    n00b_add_rule_v(g, list_id, 1,
                     (n00b_match_t[]){NT(item_id)});
    n00b_add_rule_v(g, list_id, 2,
                     (n00b_match_t[]){NT(list_id), NT(item_id)});

    // item -> atom                            (rule 0: pass-through)
    //       | atom QUESTION                   (rule 1: atom?)
    //       | atom STAR                       (rule 2: atom*)
    //       | atom PLUS                       (rule 3: atom+)
    //       | LPAREN expression RPAREN                   (rule 4: bare group)
    //       | LPAREN expression RPAREN QUESTION           (rule 5: group?)
    //       | LPAREN expression RPAREN STAR               (rule 6: group*)
    //       | LPAREN expression RPAREN PLUS               (rule 7: group+)
    n00b_add_rule_v(g, item_id, 1,
                     (n00b_match_t[]){NT(atom_id)});
    n00b_add_rule_v(g, item_id, 2,
                     (n00b_match_t[]){NT(atom_id), N00B_TERMINAL(QUESTION)});
    n00b_add_rule_v(g, item_id, 2,
                     (n00b_match_t[]){NT(atom_id), N00B_TERMINAL(STAR)});
    n00b_add_rule_v(g, item_id, 2,
                     (n00b_match_t[]){NT(atom_id), N00B_TERMINAL(PLUS_OP)});
    n00b_add_rule_v(g, item_id, 3,
                     (n00b_match_t[]){N00B_TERMINAL(LPAREN), NT(expression_id),
                                      N00B_TERMINAL(RPAREN)});
    n00b_add_rule_v(g, item_id, 4,
                     (n00b_match_t[]){N00B_TERMINAL(LPAREN), NT(expression_id),
                                      N00B_TERMINAL(RPAREN), N00B_TERMINAL(QUESTION)});
    n00b_add_rule_v(g, item_id, 4,
                     (n00b_match_t[]){N00B_TERMINAL(LPAREN), NT(expression_id),
                                      N00B_TERMINAL(RPAREN), N00B_TERMINAL(STAR)});
    n00b_add_rule_v(g, item_id, 4,
                     (n00b_match_t[]){N00B_TERMINAL(LPAREN), NT(expression_id),
                                      N00B_TERMINAL(RPAREN), N00B_TERMINAL(PLUS_OP)});

    // atom -> LITERAL | LANGLE NAME RANGLE | CLASS | TOKEN_TYPE | TOKEN_LIT | EMPTY_LIT
    //       | CAPTURE_DECL LANGLE NAME RANGLE   (rule 6: $name:<nt> inline capture)
    n00b_add_rule_v(g, atom_id, 1,
                     (n00b_match_t[]){N00B_TERMINAL(LITERAL)});
    n00b_add_rule_v(g, atom_id, 3,
                     (n00b_match_t[]){N00B_TERMINAL(LANGLE), N00B_TERMINAL(NAME),
                                      N00B_TERMINAL(RANGLE)});
    n00b_add_rule_v(g, atom_id, 1,
                     (n00b_match_t[]){N00B_TERMINAL(CLASS)});
    n00b_add_rule_v(g, atom_id, 1,
                     (n00b_match_t[]){N00B_TERMINAL(TOKEN_TYPE)});
    n00b_add_rule_v(g, atom_id, 1,
                     (n00b_match_t[]){N00B_TERMINAL(TOKEN_LIT)});
    n00b_add_rule_v(g, atom_id, 1,
                     (n00b_match_t[]){N00B_TERMINAL(EMPTY_LIT)});
    n00b_add_rule_v(g, atom_id, 4,
                     (n00b_match_t[]){N00B_TERMINAL(CAPTURE_DECL),
                                      N00B_TERMINAL(LANGLE),
                                      N00B_TERMINAL(NAME),
                                      N00B_TERMINAL(RANGLE)});

    // annotations -> "" | annotation annotations
    n00b_add_rule_v(g, annotations_id, 1,
                     (n00b_match_t[]){N00B_EPSILON()});
    n00b_add_rule_v(g, annotations_id, 2,
                     (n00b_match_t[]){NT(annotation_id), NT(annotations_id)});

    // annotation -> AT NAME LPAREN arg-list RPAREN | AT NAME
    n00b_add_rule_v(g, annotation_id, 5,
                     (n00b_match_t[]){N00B_TERMINAL(AT), N00B_TERMINAL(NAME),
                                      N00B_TERMINAL(LPAREN), NT(arg_list_id),
                                      N00B_TERMINAL(RPAREN)});
    n00b_add_rule_v(g, annotation_id, 2,
                     (n00b_match_t[]){N00B_TERMINAL(AT), N00B_TERMINAL(NAME)});

    // arg-list -> annot-arg | arg-list COMMA annot-arg
    n00b_add_rule_v(g, arg_list_id, 1,
                     (n00b_match_t[]){NT(annot_arg_id)});
    n00b_add_rule_v(g, arg_list_id, 3,
                     (n00b_match_t[]){NT(arg_list_id), N00B_TERMINAL(COMMA),
                                      NT(annot_arg_id)});

    // annot-arg -> LITERAL | DOLLAR | NAME | EMPTY_LIT
    n00b_add_rule_v(g, annot_arg_id, 1,
                     (n00b_match_t[]){N00B_TERMINAL(LITERAL)});
    n00b_add_rule_v(g, annot_arg_id, 1,
                     (n00b_match_t[]){N00B_TERMINAL(DOLLAR)});
    n00b_add_rule_v(g, annot_arg_id, 1,
                     (n00b_match_t[]){N00B_TERMINAL(NAME)});
    n00b_add_rule_v(g, annot_arg_id, 1,
                     (n00b_match_t[]){N00B_TERMINAL(EMPTY_LIT)});

#undef NT

    // Set walk actions — use n00b_get_nonterm for fresh pointers
    // (safe since no further grammar mutations follow).
    n00b_nonterm_set_action(n00b_get_nonterm(g, syntax_id), bnf_walk_syntax);
    n00b_nonterm_set_action(n00b_get_nonterm(g, rule_id), bnf_walk_rule);
    n00b_nonterm_set_action(n00b_get_nonterm(g, expression_id), bnf_walk_expression);
    n00b_nonterm_set_action(n00b_get_nonterm(g, list_id), bnf_walk_list);
    n00b_nonterm_set_action(n00b_get_nonterm(g, item_id), bnf_walk_item);
    n00b_nonterm_set_action(n00b_get_nonterm(g, atom_id), bnf_walk_atom);
    n00b_nonterm_set_action(n00b_get_nonterm(g, annotations_id), bnf_walk_annotations);
    n00b_nonterm_set_action(n00b_get_nonterm(g, annotation_id), bnf_walk_annotation);
    n00b_nonterm_set_action(n00b_get_nonterm(g, arg_list_id), bnf_walk_arg_list);
    n00b_nonterm_set_action(n00b_get_nonterm(g, annot_arg_id), bnf_walk_annot_arg);

    return g;
}

// ============================================================================
// Reserved terminal -> character class mapping
// ============================================================================

static bool
reserved_to_class(n00b_string_t *name, n00b_char_class_t *cc_out)
{
    if (!name) {
        return false;
    }

    struct {
        n00b_string_t    *lit;
        n00b_char_class_t cc;
    } map[] = {
        {r"__DIGIT",          N00B_CC_ASCII_DIGIT       },
        {r"__ALPHA",          N00B_CC_ASCII_ALPHA        },
        {r"__UPPER",          N00B_CC_ASCII_UPPER        },
        {r"__LOWER",          N00B_CC_ASCII_LOWER        },
        {r"__HEX",            N00B_CC_HEX_DIGIT          },
        {r"__NONZERO_DIGIT",  N00B_CC_NONZERO_DIGIT      },
        {r"__WHITESPACE",     N00B_CC_WHITESPACE          },
        {r"__WS",             N00B_CC_WHITESPACE          },
        {r"__ID_START",       N00B_CC_ID_START            },
        {r"__ID_CONTINUE",    N00B_CC_ID_CONTINUE         },
        {r"__PRINTABLE",      N00B_CC_PRINTABLE           },
        {r"__UNICODE_DIGIT",  N00B_CC_UNICODE_DIGIT       },
        {r"__JSON_STR",       N00B_CC_JSON_STRING_CHAR    },
        {r"__REGEX_STR",      N00B_CC_REGEX_BODY_CHAR     },
        {NULL,                0                          },
    };

    for (int i = 0; map[i].lit; i++) {
        if (str_eq_lit(name, map[i].lit)) {
            *cc_out = map[i].cc;
            return true;
        }
    }

    return false;
}

// token_type_to_id removed — literal type IDs are now dynamic.
// Use n00b_register_literal_type(g, name) instead.

// ============================================================================
// Convert walk results into grammar rules
// ============================================================================

// Counter for anonymous nonterminals generated by EBNF groups.
static int bnf_anon_counter = 0;

// Pending capture collected during term resolution. Allocated as
// transient state by populate_grammar; attached to the rule after
// the rule is created.
typedef struct {
    n00b_string_t *name;
    int32_t        child_ix;
} bnf_pending_capture_t;

// Resolve a single tagged term string into match items appended to a
// dynamic array.  Returns the new count; *items_p and *cap_p may be
// reallocated. If `captures_out` is non-nullptr and the term carries
// capture metadata ('P:' prefix), a (name, child_ix) entry is pushed
// onto the list. `child_ix` is taken from the current value of `n`
// (= the position this match will occupy in the rule body).
static int
resolve_term_to_matches(n00b_grammar_t *user_g,
                        const char     *tagged,
                        n00b_match_t  **items_p,
                        int            *cap_p,
                        int             n,
                        bnf_list_t     *captures_out)
{
    if (!tagged || strlen(tagged) < 2) {
        return n;
    }

    n00b_match_t *items = *items_p;
    int           cap   = *cap_p;
    char          type  = tagged[0];
    const char   *val   = tagged + 2;
    n00b_string_t *val_s  = n00b_string_from_cstr(val);

    switch (type) {
    case 'L': {
        const char *p = val;

        while (*p) {
            const char *start = p;
            int32_t     cp    = utf8_decode(&p);

            if (cp < 0) {
                break;
            }

            // Hash the UTF-8 bytes of this codepoint to get the terminal ID.
            size_t  cp_len = (size_t)(p - start);
            int64_t tid    = n00b_token_id_from_text(start, cp_len);

            // Register it as a terminal so valid_tokens and terminal_by_id
            // are populated.
            n00b_string_t *cp_str = n00b_string_from_raw(start, (int64_t)cp_len);
            n00b_register_terminal(user_g, cp_str);

            if (n >= cap) {
                int old_cap = cap;
                cap = cap ? cap * 2 : 8;
                n00b_match_t *new_items = n00b_alloc_array(n00b_match_t, (size_t)cap);
                if (items && old_cap > 0)
                    memcpy(new_items, items, (size_t)old_cap * sizeof(n00b_match_t));
                if (items) n00b_free(items);
                items = new_items;
            }

            items[n++] = (n00b_match_t){
                .kind        = N00B_MATCH_TERMINAL,
                .terminal_id = tid,
            };
        }

        break;
    }
    case 'N': {
        int64_t ref_id = n00b_nonterm(user_g, val_s)->id;

        if (n >= cap) {
            int old_cap = cap;
            cap = cap ? cap * 2 : 8;
            n00b_match_t *new_items = n00b_alloc_array(n00b_match_t, (size_t)cap);
            if (items && old_cap > 0)
                memcpy(new_items, items, (size_t)old_cap * sizeof(n00b_match_t));
            if (items) n00b_free(items);
            items = new_items;
        }

        items[n++] = (n00b_match_t){
            .kind  = N00B_MATCH_NT,
            .nt_id = ref_id,
        };
        break;
    }
    case 'C': {
        n00b_char_class_t cc;

        if (reserved_to_class(val_s, &cc)) {
            if (n >= cap) {
                int old_cap = cap;
                cap = cap ? cap * 2 : 8;
                n00b_match_t *new_items = n00b_alloc_array(n00b_match_t, (size_t)cap);
                if (items && old_cap > 0)
                    memcpy(new_items, items, (size_t)old_cap * sizeof(n00b_match_t));
                if (items) n00b_free(items);
                items = new_items;
            }

            items[n++] = (n00b_match_t){
                .kind       = N00B_MATCH_CLASS,
                .char_class = cc,
            };
        }

        break;
    }
    case 'T': {
        // Register the literal type name (e.g. "IDENTIFIER", "INTEGER")
        // and get back its small sequential ID.
        int64_t tok_id = n00b_register_literal_type(user_g, val_s);

        if (n >= cap) {
            int old_cap = cap;
            cap = cap ? cap * 2 : 8;
            n00b_match_t *new_items = n00b_alloc_array(n00b_match_t, (size_t)cap);
            if (items && old_cap > 0)
                memcpy(new_items, items, (size_t)old_cap * sizeof(n00b_match_t));
            if (items) n00b_free(items);
            items = new_items;
        }

        items[n++] = (n00b_match_t){
            .kind        = N00B_MATCH_TERMINAL,
            .terminal_id = tok_id,
        };

        break;
    }
    case 'K': {
        int64_t term_id = n00b_register_terminal(user_g, val_s);

        if (n >= cap) {
            int old_cap = cap;
            cap = cap ? cap * 2 : 8;
            n00b_match_t *new_items = n00b_alloc_array(n00b_match_t, (size_t)cap);
            if (items && old_cap > 0)
                memcpy(new_items, items, (size_t)old_cap * sizeof(n00b_match_t));
            if (items) n00b_free(items);
            items = new_items;
        }

        items[n++] = (n00b_match_t){
            .kind        = N00B_MATCH_TERMINAL,
            .terminal_id = term_id,
        };

        break;
    }
    case 'E': {
        if (n >= cap) {
            int old_cap = cap;
            cap = cap ? cap * 2 : 8;
            n00b_match_t *new_items = n00b_alloc_array(n00b_match_t, (size_t)cap);
            if (items && old_cap > 0)
                memcpy(new_items, items, (size_t)old_cap * sizeof(n00b_match_t));
            if (items) n00b_free(items);
            items = new_items;
        }

        items[n++] = (n00b_match_t){
            .kind = N00B_MATCH_EMPTY,
        };

        break;
    }
    case 'P': {
        // P:capname\0ntname\0 — inline capture declaration. Layout
        // matches the producer in bnf_walk_atom: val[0]..nul = cap
        // name, then nul-separated nt name, then trailing nul.
        const char *cap_name = val;
        size_t      cap_len  = strlen(cap_name);
        const char *nt_name  = cap_name + cap_len + 1;
        n00b_string_t *cap_s = n00b_string_from_raw((char *)cap_name,
                                                     (int64_t)cap_len);
        n00b_string_t *nt_s  = n00b_string_from_cstr(nt_name);

        if (captures_out) {
            bnf_pending_capture_t *pc = n00b_alloc(bnf_pending_capture_t);
            pc->name     = cap_s;
            pc->child_ix = (int32_t)n;
            n00b_list_push(*captures_out, pc);
        }

        int64_t ref_id = n00b_nonterm(user_g, nt_s)->id;

        if (n >= cap) {
            int old_cap = cap;
            cap = cap ? cap * 2 : 8;
            n00b_match_t *new_items = n00b_alloc_array(n00b_match_t, (size_t)cap);
            if (items && old_cap > 0)
                memcpy(new_items, items, (size_t)old_cap * sizeof(n00b_match_t));
            if (items) n00b_free(items);
            items = new_items;
        }

        items[n++] = (n00b_match_t){
            .kind  = N00B_MATCH_NT,
            .nt_id = ref_id,
        };
        break;
    }
    }

    *items_p = items;
    *cap_p   = cap;

    return n;
}

// Resolve a list of BNF_STRING/BNF_GROUP term results into a n00b_match_t
// array.  Appends to *items_p starting at position n.
static int
resolve_terms_to_matches(n00b_grammar_t *user_g,
                         bnf_list_t  *terms,
                         n00b_match_t  **items_p,
                         int            *cap_p,
                         int             n,
                         bnf_list_t     *captures_out);

// Resolve a BNF_GROUP into a single n00b_match_t and append it.
static int
resolve_group_to_match(n00b_grammar_t    *user_g,
                       bnf_group_info_t  *gi,
                       n00b_match_t     **items_p,
                       int               *cap_p,
                       int                n)
{
    int min = 0, max = 0;

    switch (gi->quantifier) {
    case '?': min = 0; max = 1; break;
    case '*': min = 0; max = 0; break;
    case '+': min = 1; max = 0; break;
    default:  min = 1; max = 1; break;  // bare group = exactly once
    }

    n00b_match_t group_match;

    if (gi->alternatives->len == 1) {
        // Single alternative: resolve its terms into a match array, then
        // call n00b_group_match_v.
        bnf_result_t  *alt_r        = slist_get(gi->alternatives, 0);
        bnf_list_t *inner        = (bnf_list_t *)alt_r->data;
        n00b_match_t  *inner_items  = NULL;
        int            inner_cap    = 0;
        int            inner_n      = 0;

        inner_n = resolve_terms_to_matches(
            user_g, inner, &inner_items, &inner_cap, inner_n, nullptr);

        if (inner_n > 0) {
            group_match = n00b_group_match_v(
                user_g, min, max, inner_n, inner_items);
        }
        else {
            n00b_free(inner_items);
            return n;
        }

        n00b_free(inner_items);
    }
    else {
        // Multiple alternatives: create anonymous nonterminal with one
        // rule per alternative, then wrap the NT reference in a group.
        char namebuf[64];
        snprintf(namebuf, sizeof(namebuf),
                 "$$bnf_anon_%d", bnf_anon_counter++);
        n00b_string_t  *name_s  = n00b_string_from_cstr(namebuf);
        n00b_nonterm_t *anon_nt = n00b_nonterm(user_g, name_s);
        int64_t         anon_id = anon_nt->id;

        for (size_t ai = 0; ai < gi->alternatives->len; ai++) {
            bnf_result_t  *alt_r      = slist_get(gi->alternatives, ai);
            bnf_list_t *inner      = (bnf_list_t *)alt_r->data;
            n00b_match_t  *alt_items  = NULL;
            int            alt_cap    = 0;
            int            alt_n      = 0;

            alt_n = resolve_terms_to_matches(
                user_g, inner, &alt_items, &alt_cap, alt_n, nullptr);

            if (alt_n > 0) {
                n00b_add_rule_v(user_g, anon_id, alt_n, alt_items);
            }
            else {
                n00b_match_t empty = {.kind = N00B_MATCH_EMPTY};
                n00b_add_rule_v(user_g, anon_id, 1, &empty);
            }

            n00b_free(alt_items);
        }

        // Wrap anonymous NT in a group match.
        n00b_match_t nt_match = {
            .kind  = N00B_MATCH_NT,
            .nt_id = anon_id,
        };

        group_match = n00b_group_match_v(user_g, min, max, 1, &nt_match);
    }

    n00b_match_t *items = *items_p;
    int           cap   = *cap_p;

    if (n >= cap) {
        int old_cap = cap;
        cap = cap ? cap * 2 : 8;
        n00b_match_t *new_items = n00b_alloc_array(n00b_match_t, (size_t)cap);
        if (items && old_cap > 0)
            memcpy(new_items, items, (size_t)old_cap * sizeof(n00b_match_t));
        if (items) n00b_free(items);
        items = new_items;
    }

    items[n++] = group_match;
    *items_p   = items;
    *cap_p     = cap;

    return n;
}

static int
resolve_terms_to_matches(n00b_grammar_t *user_g,
                         bnf_list_t  *terms,
                         n00b_match_t  **items_p,
                         int            *cap_p,
                         int             n,
                         bnf_list_t     *captures_out)
{
    for (size_t ti = 0; ti < terms->len; ti++) {
        bnf_result_t *term_r = slist_get(terms, ti);

        if (term_r->tag == BNF_GROUP) {
            n = resolve_group_to_match(
                user_g, (bnf_group_info_t *)term_r->data, items_p, cap_p, n);
        }
        else {
            n = resolve_term_to_matches(
                user_g, (char *)term_r->data, items_p, cap_p, n,
                captures_out);
        }
    }

    return n;
}

// Attach a parsed BNF annotation to a rule.
// Converts bnf_annot_info_t fields into an n00b_annotation_t and appends
// it to the rule's annotation list.  Skips @tokenizer and @penalty
// (handled elsewhere).
static void
attach_annot_to_rule(n00b_parse_rule_t *rule_p, bnf_annot_info_t *info)
{
    if (!rule_p || !info) {
        return;
    }

    if (info->kind == N00B_ANNOT_TOKENIZER || info->kind == N00B_ANNOT_PENALTY) {
        return;
    }

    n00b_annotation_t annot = {0};
    annot.kind           = info->kind;
    annot.name_ref       = info->name_ref;
    annot.type_ref       = info->type_ref;
    annot.value_ref      = info->value_ref;
    annot.scope_tag      = info->scope_tag;
    annot.capture_by_tag = info->capture_by_tag;
    annot.type_spec      = info->type_spec;
    annot.infer_expr     = info->infer_expr;
    annot.adt_kind       = info->adt_kind;
    annot.visibility_spec  = info->visibility_spec;
    annot.op_kind          = info->op_kind;
    annot.notrivia_ref     = info->notrivia_ref;
    annot.sym_kind         = info->sym_kind;
    annot.adt_keyword_ref  = info->adt_keyword_ref;

    n00b_rule_annotate(rule_p, annot);
}

// Helper: push a BNF diagnostic (to diag if available, always to stderr).
static void
bnf_diag(n00b_diag_ctx_t *diag, n00b_diag_severity_t sev,
         n00b_string_t *code, n00b_string_t *msg, n00b_diag_span_t span)
{
    if (diag) {
        n00b_diag_push(diag, sev, N00B_STAGE_PARSE, code, msg, span);
    }

    const char *sev_str = (sev == N00B_DIAG_ERROR)   ? "error"
                        : (sev == N00B_DIAG_WARNING) ? "warning"
                                                     : "note";
    fprintf(stderr, "bnf %s[%.*s]: %.*s",
            sev_str,
            (int)code->u8_bytes, code->data,
            (int)msg->u8_bytes, msg->data);

    if (span.start_line > 0) {
        fprintf(stderr, " (line %u, col %u)", span.start_line, span.start_col);
    }

    fprintf(stderr, "\n");
}

static bool
populate_grammar(n00b_grammar_t *user_g, bnf_result_t *result,
                 n00b_string_t *start_symbol, n00b_diag_ctx_t *diag)
{
    if (!result || result->tag != BNF_DICT) {
        bnf_diag(diag, N00B_DIAG_ERROR, r"B010",
                 r"BNF walk result is not a rule dictionary (internal error)",
                 (n00b_diag_span_t){0});
        return false;
    }

    bnf_list_t *pairs = (bnf_list_t *)result->data;

    if (!pairs || !pairs->len) {
        bnf_diag(diag, N00B_DIAG_ERROR, r"B011",
                 r"BNF grammar contains no rules",
                 (n00b_diag_span_t){0});
        return false;
    }

    n00b_string_t *first_name = NULL;

    // First pass: create all non-terminals and handle grammar-level annotations.
    for (size_t i = 0; i < pairs->len; i++) {
        bnf_result_t  *pair_r = slist_get(pairs, i);
        bnf_list_t    *pair   = (bnf_list_t *)pair_r->data;
        bnf_result_t  *name_r = slist_get(pair, 0);
        n00b_string_t *name   = (n00b_string_t *)name_r->data;

        bool is_grammar_annot = (!name || !name->data || name->data[0] == '\0');

        if (!is_grammar_annot) {
            n00b_nonterm(user_g, name);

            if (!first_name) {
                first_name = name;
            }
        }

        // Handle grammar-level annotations (e.g. @tokenizer) in pass 1.
        bnf_result_t *annots_r = (pair->len >= 3) ? slist_get(pair, 2) : NULL;

        if (annots_r && annots_r->tag == BNF_LIST) {
            bnf_list_t *annot_list = (bnf_list_t *)annots_r->data;

            for (size_t j = 0; j < annot_list->len; j++) {
                bnf_result_t *a_r = slist_get(annot_list, j);

                if (a_r && a_r->tag == BNF_ANNOT) {
                    bnf_annot_info_t *info = (bnf_annot_info_t *)a_r->data;

                    if (info->kind == N00B_ANNOT_TOKENIZER) {
                        if (info->scope_tag->data) {
                            user_g->tokenizer_name = info->scope_tag;
                        }
                    }
                }
            }
        }
    }

    // Set start symbol.
    n00b_string_t *start_s;

    if (start_symbol) {
        start_s = start_symbol;
    }
    else if (first_name) {
        start_s = first_name;
    }
    else {
        bnf_diag(diag, N00B_DIAG_ERROR, r"B012",
                 r"no start symbol specified and grammar has no rules",
                 (n00b_diag_span_t){0});
        return false;
    }

    n00b_grammar_set_start_id(user_g,
        n00b_nonterm_id(n00b_nonterm(user_g, start_s)));

    // Second pass: create rules.
    for (size_t i = 0; i < pairs->len; i++) {
        bnf_result_t  *pair_r = slist_get(pairs, i);
        bnf_list_t *pair   = (bnf_list_t *)pair_r->data;
        bnf_result_t  *name_r = slist_get(pair, 0);
        bnf_result_t  *expr_r = slist_get(pair, 1);
        n00b_string_t *name   = (n00b_string_t *)name_r->data;

        // Skip grammar-level annotation entries (no rules to add).
        if (!name || !name->data || name->data[0] == '\0' || !expr_r) {
            continue;
        }

        // Check for @penalty annotation on this rule line.
        int32_t penalty_cost = 0;
        bnf_result_t *annots_r = (pair->len >= 3) ? slist_get(pair, 2) : NULL;

        if (annots_r && annots_r->tag == BNF_LIST) {
            bnf_list_t *annot_list = (bnf_list_t *)annots_r->data;

            for (size_t j = 0; j < annot_list->len; j++) {
                bnf_result_t *a_r = slist_get(annot_list, j);

                if (a_r && a_r->tag == BNF_ANNOT) {
                    bnf_annot_info_t *info = (bnf_annot_info_t *)a_r->data;

                    if (info->kind == N00B_ANNOT_PENALTY) {
                        penalty_cost = info->penalty_cost;
                    }
                }
            }
        }

        int64_t nt_id = n00b_nonterm(user_g, name)->id;

        bnf_list_t *alternatives = (bnf_list_t *)expr_r->data;

        // Optional rewrite-block body for this LHS (taken from the
        // 4th element of the rule pair, populated by bnf_walk_rule).
        n00b_string_t *rewrite_body = nullptr;
        if (pair->len >= 4) {
            bnf_result_t *rw_r = slist_get(pair, 3);
            if (rw_r) {
                rewrite_body = (n00b_string_t *)rw_r->data;
            }
        }

        for (size_t ai = 0; ai < alternatives->len; ai++) {
            bnf_result_t  *alt_r = slist_get(alternatives, ai);
            bnf_list_t *terms = (bnf_list_t *)alt_r->data;
            n00b_match_t  *items = NULL;
            int            n     = 0;
            int            cap   = 0;

            bnf_list_t *pending_captures = slist_new();

            n = resolve_terms_to_matches(user_g, terms, &items, &cap, n,
                                          pending_captures);

            n00b_parse_rule_t  *rule_p = NULL;

            if (penalty_cost > 0) {
                if (n > 0) {
                    rule_p = n00b_add_rule_with_cost_v(
                        user_g, nt_id, penalty_cost, n, items);
                }
                else {
                    n00b_match_t empty = {.kind = N00B_MATCH_EMPTY};
                    rule_p = n00b_add_rule_with_cost_v(
                        user_g, nt_id, penalty_cost, 1, &empty);
                }

                if (rule_p) {
                    rule_p->penalty_rule = true;
                }
            }
            else {
                if (n > 0) {
                    rule_p = n00b_add_rule_v(user_g, nt_id, n, items);
                }
                else {
                    n00b_match_t empty = {.kind = N00B_MATCH_EMPTY};
                    rule_p = n00b_add_rule_v(user_g, nt_id, 1, &empty);
                }
            }

            // Attach this block's annotations to the newly created rule.
            if (rule_p && annots_r && annots_r->tag == BNF_LIST) {
                bnf_list_t *annot_list = (bnf_list_t *)annots_r->data;

                for (size_t j = 0; j < annot_list->len; j++) {
                    bnf_result_t *a_r = slist_get(annot_list, j);

                    if (a_r && a_r->tag == BNF_ANNOT) {
                        attach_annot_to_rule(
                            rule_p, (bnf_annot_info_t *)a_r->data);
                    }
                }
            }

            // Attach captures collected during term resolution.
            if (rule_p) {
                for (size_t ci = 0; ci < pending_captures->len; ci++) {
                    bnf_pending_capture_t *pc = slist_get(pending_captures, ci);
                    _n00b_production_add_capture(rule_p, pc->name, pc->child_ix);
                }

                // Attach the rewrite block (if any) to every rule for
                // this LHS. Per design, alternatives share one rewrite.
                if (rewrite_body && rewrite_body->u8_bytes > 0) {
                    _n00b_production_attach_rewrite(rule_p, rewrite_body);
                }
            }

            // pending_captures contents are now owned by the production;
            // the list wrapper itself can be released.
            slist_free(pending_captures);

            n00b_free(items);
        }
    }

    // Validate: @type requires @declares on the same rule.
    for (size_t ri = 0; ri < user_g->rules.len; ri++) {
        n00b_parse_rule_t *rule = &user_g->rules.data[ri];

        if (!rule->annotations.data) {
            continue;
        }

        bool has_type     = false;
        bool has_declares = false;

        for (size_t ai = 0; ai < n00b_list_len(rule->annotations); ai++) {
            n00b_annotation_t *a = n00b_list_get(rule->annotations, ai);

            if (a->kind == N00B_ANNOT_TYPE) {
                has_type = true;
            }

            if (a->kind == N00B_ANNOT_DECLARES) {
                has_declares = true;
            }
        }

        if (has_type && !has_declares) {
            n00b_nonterm_t *nt = n00b_get_nonterm(user_g, rule->nt_id);
            const char *nt_name = (nt && nt->name && nt->name->data) ? nt->name->data : "?";
            char msg_buf[256];
            snprintf(msg_buf, sizeof(msg_buf),
                     "@type requires @declares on <%s>", nt_name);
            bnf_diag(diag, N00B_DIAG_ERROR, r"B013",
                     n00b_string_from_cstr(msg_buf),
                     (n00b_diag_span_t){0});
            return false;
        }
    }

    n00b_grammar_finalize(user_g);

    return true;
}

// ============================================================================
// Free walk results recursively
// ============================================================================

static void
free_bnf_result(bnf_result_t *r)
{
    if (!r) {
        return;
    }

    switch (r->tag) {
    case BNF_STRING:
        // Tagged protocol strings (char *) allocated via n00b_alloc.
        n00b_free(r->data);
        break;

    case BNF_NAME:
        // Heap-allocated n00b_string_t * (rule names from walk_rule/walk_syntax).
        // The .data inside is owned by the token/scanner, not us.
        n00b_free(r->data);
        break;

    case BNF_LIST: {
        bnf_list_t *l = (bnf_list_t *)r->data;

        for (size_t i = 0; i < l->len; i++) {
            free_bnf_result(slist_get(l, i));
        }

        slist_free(l);
        break;
    }

    case BNF_PAIR: {
        bnf_list_t *pair = (bnf_list_t *)r->data;

        for (size_t i = 0; i < pair->len; i++) {
            free_bnf_result(slist_get(pair, i));
        }

        slist_free(pair);
        break;
    }

    case BNF_DICT: {
        bnf_list_t *pairs = (bnf_list_t *)r->data;

        for (size_t i = 0; i < pairs->len; i++) {
            free_bnf_result(slist_get(pairs, i));
        }

        slist_free(pairs);
        break;
    }

    case BNF_GROUP: {
        bnf_group_info_t *gi = (bnf_group_info_t *)r->data;

        if (gi->alternatives) {
            for (size_t i = 0; i < gi->alternatives->len; i++) {
                free_bnf_result(slist_get(gi->alternatives, i));
            }

            slist_free(gi->alternatives);
        }

        n00b_free(gi);
        break;
    }

    case BNF_ANNOT: {
        // Fields are n00b_string_t * pointers from tok_str(); their .data is
        // owned by the scanner/token stream, not us.  Just free the struct.
        bnf_annot_info_t *info = (bnf_annot_info_t *)r->data;
        n00b_free(info);
        break;
    }
    }

    n00b_free(r);
}

// ============================================================================
// Public API
// ============================================================================

bool
n00b_bnf_load(n00b_string_t  *bnf_text,
              n00b_string_t  *start_symbol,
              n00b_grammar_t *user_g) _kargs {
    n00b_parse_fn_t   parse_fn;
    n00b_diag_ctx_t  *diag;
}
{
    (void)parse_fn;
    (void)diag;

    n00b_diag_ctx_t *dx = kargs->diag;

    if (!bnf_text || !user_g) {
        bnf_diag(dx, N00B_DIAG_ERROR, r"B000",
                 r"n00b_bnf_load: NULL input text or grammar",
                 (n00b_diag_span_t){0});
        return false;
    }

    // Preprocess.
    n00b_string_t *stripped = n00b_bnf_strip_comments(bnf_text);
    n00b_string_t *trimmed  = n00b_bnf_trim_lines(stripped);

    // Join continuation lines (lines starting with '|' are
    // merged with the preceding line).
    trimmed = bnf_join_continuations(trimmed);

    // Ensure text ends with a newline.
    size_t len = trimmed->u8_bytes;

    if (len > 0 && trimmed->data[len - 1] != '\n') {
        char *tmp = n00b_alloc_array(char, len + 2);
        memcpy(tmp, trimmed->data, len);
        tmp[len]     = '\n';
        tmp[len + 1] = '\0';
        trimmed = n00b_string_from_raw(tmp, (int64_t)(len + 1));
    }

    // Tokenize using the scanner API.
    n00b_buffer_t       *bnf_buf  = n00b_buffer_from_bytes(trimmed->data,
                                                           (int64_t)trimmed->u8_bytes);
    bool                 in_angle = false;
    n00b_scanner_t      *bnf_sc   = n00b_scanner_new(bnf_buf, bnf_scan, NULL,
                                                      .state = &in_angle);
    n00b_token_stream_t *bnf_ts   = n00b_token_stream_new(bnf_sc);
    n00b_list_t(n00b_token_info_t)    bnf_tl   = n00b_stream_collect(bnf_ts);

    if (n00b_list_len(bnf_tl) == 0) {
        bnf_diag(dx, N00B_DIAG_ERROR, r"B001",
                 r"BNF tokenizer produced no tokens (empty or unparseable input)",
                 (n00b_diag_span_t){0});
        n00b_list_free(bnf_tl);
        n00b_token_stream_free(bnf_ts);
        n00b_scanner_free(bnf_sc);
        n00b_buffer_free(bnf_buf);
        return false;
    }

    // Build token pointer array and wrap as a new stream for the parser.
    n00b_token_info_ptr_t *raw_ptrs;
    int32_t                bnf_n = n00b_token_list_build_ptrs(&bnf_tl, &raw_ptrs);

    n00b_token_stream_t *parse_ts
        = n00b_token_stream_from_array(raw_ptrs, bnf_n);

    // Build the BNF meta-grammar and parse. WP-017: use PWZ_ONLY —
    // the BNF metagrammar is unambiguous; falling back to Earley
    // here is a perf trap that hides genuine BNF errors behind
    // hours of Earley-chart grinding.
    n00b_grammar_t      *meta_g = build_bnf_grammar();
    n00b_parse_result_t *pr     = n00b_parse(meta_g, parse_ts,
                                              (n00b_parse_opts_t){0});

    if (!n00b_parse_result_ok(pr)) {
        // Extract the rich error string from the Earley chart.
        n00b_string_t *err = n00b_parse_result_error_string(pr);
        n00b_error_location_t loc = n00b_parse_result_error_location(pr);
        n00b_diag_span_t span = {
            .start_line = loc.line,
            .start_col  = loc.column,
        };

        bnf_diag(dx, N00B_DIAG_ERROR, r"B002", err, span);

        n00b_parse_result_free(pr);
        n00b_free(raw_ptrs);
        n00b_token_stream_free(parse_ts);
        n00b_list_free(bnf_tl);
        n00b_token_stream_free(bnf_ts);
        n00b_scanner_free(bnf_sc);
        n00b_buffer_free(bnf_buf);
        n00b_grammar_free(meta_g);
        return false;
    }

    // Walk the parse tree using BNF walk actions.
    bnf_result_t *result = (bnf_result_t *)n00b_parse_result_walk(pr, NULL, NULL);

    if (!result) {
        bnf_diag(dx, N00B_DIAG_ERROR, r"B003",
                 r"BNF parse succeeded but tree walk produced no result",
                 (n00b_diag_span_t){0});
        n00b_parse_result_free(pr);
        n00b_free(raw_ptrs);
        n00b_token_stream_free(parse_ts);
        n00b_list_free(bnf_tl);
        n00b_token_stream_free(bnf_ts);
        n00b_scanner_free(bnf_sc);
        n00b_buffer_free(bnf_buf);
        n00b_grammar_free(meta_g);
        return false;
    }

    bool success = populate_grammar(user_g, result, start_symbol, dx);

    free_bnf_result(result);
    n00b_parse_result_free(pr);
    n00b_free(raw_ptrs);
    n00b_token_stream_free(parse_ts);
    n00b_list_free(bnf_tl);
    n00b_token_stream_free(bnf_ts);
    n00b_scanner_free(bnf_sc);
    n00b_buffer_free(bnf_buf);
    n00b_grammar_free(meta_g);

    return success;
}

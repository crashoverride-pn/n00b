/*
 * Parser for resharp regex patterns.  Faithful translation of upstream Rust
 * resharp-parser, with primitives translated to n00b idioms:
 *   - allocate by type (n00b_alloc / n00b_alloc_array) — no xalloc shim;
 *   - n00b_require / n00b_panic / n00b_unreachable in place of the
 *     resharp-c require / panic / unreachable macro family;
 *   - <stdckdint.h> directly for checked-arithmetic on attacker-influenced
 *     size_t computations;
 *   - n00b_buffer_t (with .no_lock = true) in place of resharp-c's strbuf
 *     for parse-time scratch, per D12 — char * stays for owned cstr drains.
 *
 * Cross-file dependencies (algebra / unicode_classes / ast) come from the
 * sibling regex headers.
 */

#include "n00b.h"
#include "adt/variant.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "adt/list.h"
#include "adt/option.h"
#include "util/assert.h"
#include "util/panic.h"

#include "internal/regex/parser.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdckdint.h>
#include <string.h> // memcpy / memmove / memcmp (D13)

// ---------------------------------------------------------------------------
// Internal externs from sibling regex TUs.  These are NOT in algebra.h /
// unicode_classes_mod.h: they are extra surface used only by the parser.
// (Phase 6/ast.c provides the rs_* / ast_* surface; the algebra side
// already publishes the regex_builder_* family.)
// ---------------------------------------------------------------------------

// `regex_builder_subsumes_known` and `regex_builder_try_elim_lookarounds`
// are declared in algebra.h.  We use them directly.

// ---------------------------------------------------------------------------
// Local <stdckdint.h> wrappers — PANIC on overflow.
// ---------------------------------------------------------------------------

[[noreturn]] static inline void parser_capacity_overflow(void)
{
    n00b_panic("parser.c: size_t arithmetic overflow");
}

static inline size_t parser_ckd_add_sz(size_t a, size_t b)
{
    size_t r;
    if (ckd_add(&r, a, b)) parser_capacity_overflow();
    return r;
}

static inline size_t parser_ckd_add3_sz(size_t a, size_t b, size_t c)
{
    return parser_ckd_add_sz(parser_ckd_add_sz(a, b), c);
}

static inline size_t parser_ckd_mul_sz(size_t a, size_t b)
{
    size_t r;
    if (ckd_mul(&r, a, b)) parser_capacity_overflow();
    return r;
}

// ---------------------------------------------------------------------------
// Small character classification helpers (UTF-8 + Unicode-scalar).
// ---------------------------------------------------------------------------

static size_t char_len_utf8(uint32_t c)
{
    if (c < 0x80u)    return 1;
    if (c < 0x800u)   return 2;
    if (c < 0x10000u) return 3;
    return 4;
}

// Decode a single UTF-8 scalar value at p[..p_len]; returns scalar and
// writes its byte length into *out_len.  Returns 0xFFFFFFFF on malformed.
static uint32_t utf8_decode_one(const char *p, size_t p_len, size_t *out_len)
{
    if (p_len == 0) {
        *out_len = 0;
        return 0xFFFFFFFFu;
    }
    uint8_t b0 = (uint8_t)p[0];
    if (b0 < 0x80u) {
        *out_len = 1;
        return b0;
    }
    if ((b0 & 0xE0u) == 0xC0u && p_len >= 2) {
        *out_len = 2;
        return ((uint32_t)(b0 & 0x1Fu) << 6)
             |  (uint32_t)((uint8_t)p[1] & 0x3Fu);
    }
    if ((b0 & 0xF0u) == 0xE0u && p_len >= 3) {
        *out_len = 3;
        return ((uint32_t)(b0 & 0x0Fu) << 12)
             | ((uint32_t)((uint8_t)p[1] & 0x3Fu) << 6)
             |  (uint32_t)((uint8_t)p[2] & 0x3Fu);
    }
    if ((b0 & 0xF8u) == 0xF0u && p_len >= 4) {
        *out_len = 4;
        return ((uint32_t)(b0 & 0x07u) << 18)
             | ((uint32_t)((uint8_t)p[1] & 0x3Fu) << 12)
             | ((uint32_t)((uint8_t)p[2] & 0x3Fu) << 6)
             |  (uint32_t)((uint8_t)p[3] & 0x3Fu);
    }
    *out_len = 1;
    return 0xFFFFFFFFu;
}

static bool char_is_ascii_alphanumeric(uint32_t c)
{
    return (c >= '0' && c <= '9')
        || (c >= 'A' && c <= 'Z')
        || (c >= 'a' && c <= 'z');
}

static bool char_is_ascii(uint32_t c) { return c < 128u; }

static bool char_is_alphabetic(uint32_t c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static bool char_is_alphanumeric(uint32_t c)
{
    return char_is_alphabetic(c) || (c >= '0' && c <= '9');
}

static bool char_is_whitespace(uint32_t c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
           c == 0x0Bu || c == 0x0Cu;
}

static bool char_is_ascii_digit(uint32_t c) { return c >= '0' && c <= '9'; }

static bool is_hex_char(uint32_t c)
{
    return char_is_ascii_digit(c)
        || (c >= 'a' && c <= 'f')
        || (c >= 'A' && c <= 'F');
}

// ---------------------------------------------------------------------------
// Primitive — small per-token tagged union (parser-internal).
// ---------------------------------------------------------------------------

typedef enum {
    PRIM_LITERAL,
    PRIM_ASSERTION,
    PRIM_DOT,
    PRIM_TOP,
    PRIM_PERL,
    PRIM_UNICODE,
} Primitive_tag;

typedef struct Primitive {
    Primitive_tag tag;
    union [[n00b::raw_union]] {
        rs_Literal      lit;
        ast_Assertion   assertion;
        rs_Span         span;
        rs_ClassPerl    perl;
        rs_ClassUnicode unicode;
    } as;
} Primitive;

// ---------------------------------------------------------------------------
// GroupState / ClassState — parser stack frames.
// ---------------------------------------------------------------------------

typedef struct GroupState_group_t {
    ast_Concat concat;
    ast_Group  group;
    bool       ignore_whitespace;
} GroupState_group_t;

typedef n00b_variant_t(GroupState_group_t,
                       ast_Alternation,
                       ast_Intersection) GroupState;

typedef struct ClassState_open_t {
    rs_ClassSetUnion  union_;
    rs_ClassBracketed set;
} ClassState_open_t;

typedef struct ClassState_op_t {
    rs_ClassSetBinaryOpKind kind;
    rs_ClassSet             lhs;
} ClassState_op_t;

typedef n00b_variant_t(ClassState_open_t, ClassState_op_t) ClassState;

// ---------------------------------------------------------------------------
// Local typed growable vectors — single-owner, single-threaded.
//
// Translated to n00b_list_t(T) with the unlocked (private) constructor:
// these vectors are parser-internal scratch (single owner, single thread,
// short lifetimes), so the rwlock from the locked default is pure overhead.
// `n00b_list_new_private(T, .allocator = p->allocator)` yields a struct with `lock = nullptr`, making
// every n00b_list_* operation lock-free, while still giving us geometric
// growth, bounds checks, and idiomatic push/pop/get/set semantics.
//
// The type aliases below preserve the original descriptive names.
// ---------------------------------------------------------------------------

typedef struct PerlClassEntry {
    bool             negated;
    rs_ClassPerlKind kind;
    NodeId           value;
} PerlClassEntry;

typedef n00b_list_t(PerlClassEntry)  VecPerlClass;
typedef n00b_list_t(ast_Comment)     VecComment;
typedef n00b_list_t(GroupState)      VecGroupState;
typedef n00b_list_t(ClassState)      VecClassState;
typedef n00b_list_t(ast_CaptureName) VecCaptureName;
typedef n00b_list_t(NodeId)          VecNodeId;

// ---------------------------------------------------------------------------
// Scratch byte buffer — translated from resharp-c's `strbuf` to n00b_buffer_t.
//
// Per D12 the n00b counterpart of resharp-c's strbuf is `n00b_buffer_t`.
// We construct it with `.no_lock = true` (single-owner, single-threaded
// parse-time scratch) so all ops are lock-free, matching the idiom
// already in use in `src/text/regex/algebra/solver.c`.
//
// The helpers below mirror the original push_byte / push_char / dup
// surface in n00b idiom.  `n00b_buffer_t` exposes `data` and `byte_len`
// directly, so reads remain straightforward at the call sites.
// ---------------------------------------------------------------------------

// Allocate + initialize a private (unlocked) buffer.
static n00b_buffer_t *parser_scratch_new(void)
{
    n00b_buffer_t *b = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(b, .length = 0, .no_lock = true);
    return b;
}

// Reset the buffer's content length to zero, retaining capacity.
static void parser_scratch_clear(n00b_buffer_t *b)
{
    n00b_buffer_resize(b, 0);
}

// Append a single byte.
[[maybe_unused]]
static void parser_scratch_push_byte(n00b_buffer_t *b, uint8_t byte)
{
    char c = (char)byte;
    n00b_buffer_concat(b, n00b_buffer_from_bytes(&c, 1));
}

// Append the UTF-8 encoding of one Unicode scalar.
static void parser_scratch_push_char(n00b_buffer_t *b, uint32_t c)
{
    char buf[4];
    int  n = 0;
    if (c < 0x80u) {
        buf[n++] = (char)c;
    } else if (c < 0x800u) {
        buf[n++] = (char)(0xC0u | (c >> 6));
        buf[n++] = (char)(0x80u | (c & 0x3Fu));
    } else if (c < 0x10000u) {
        buf[n++] = (char)(0xE0u | (c >> 12));
        buf[n++] = (char)(0x80u | ((c >> 6) & 0x3Fu));
        buf[n++] = (char)(0x80u | (c & 0x3Fu));
    } else {
        buf[n++] = (char)(0xF0u | (c >> 18));
        buf[n++] = (char)(0x80u | ((c >> 12) & 0x3Fu));
        buf[n++] = (char)(0x80u | ((c >> 6) & 0x3Fu));
        buf[n++] = (char)(0x80u | (c & 0x3Fu));
    }
    n00b_buffer_concat(b, n00b_buffer_from_bytes(buf, (int64_t)n));
}

// Drain the buffer's contents into a new heap-allocated NUL-terminated cstr.
// Mirrors the `buffer_into_cstr` idiom from algebra/solver.c.
static char *parser_scratch_dup_cstr(n00b_buffer_t *b)
{
    int64_t len   = 0;
    char   *src   = n00b_buffer_to_c(b, &len);
    size_t  bytes = parser_ckd_add_sz((size_t)len, 1);
    char   *out   = n00b_alloc_array(char, bytes);
    if (len > 0 && src) memcpy(out, src, (size_t)len);
    out[len] = '\0';
    return out;
}

// ---------------------------------------------------------------------------
// Inlined libc-runtime substitutes.
// We avoid <string.h> string-fns / <stdlib.h> conversions per § 15(A);
// memcpy/memset/memcmp/memmove are permitted via D13.
// ---------------------------------------------------------------------------

static size_t parser_strlen(const char *s)
{
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}

static int parser_strcmp(const char *a, const char *b)
{
    while (*a && (*a == *b)) { a++; b++; }
    return (int)(uint8_t)*a - (int)(uint8_t)*b;
}

static const char *parser_memchr_byte(const char *s, char ch, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (s[i] == ch) return s + i;
    }
    return nullptr;
}

static unsigned long parser_strtoul_n(const char *s, size_t n, int base,
                                      bool *ok)
{
    constexpr unsigned long ULMAX = (unsigned long)~0UL;
    unsigned long val = 0;
    if (n == 0) { *ok = false; return 0; }
    for (size_t i = 0; i < n; i++) {
        unsigned d;
        char c = s[i];
        if (c >= '0' && c <= '9')      d = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'z') d = (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'Z') d = (unsigned)(c - 'A' + 10);
        else { *ok = false; return 0; }
        if ((int)d >= base) { *ok = false; return 0; }
        if (val > (ULMAX - d) / (unsigned long)base) {
            *ok = false; return 0;
        }
        val = val * (unsigned long)base + d;
    }
    *ok = true;
    return val;
}

// ---------------------------------------------------------------------------
// ResharpParser — opaque struct.
// ---------------------------------------------------------------------------

struct ResharpParser {
    VecPerlClass      perl_classes;
    UnicodeClassCache unicode_classes;
    rs_Translator     translator;
    const char       *pattern;
    size_t            pattern_len;
    rs_Position       pos;
    uint32_t          capture_index;
    bool              octal;
    bool              empty_min_range;
    bool              ignore_whitespace;
    bool              dot_all;
    bool              multiline;
    bool              global_unicode;
    bool              global_full_unicode;
    bool              global_ascii_perl;
    bool              global_case_insensitive;
    uint64_t          expanded_ast_limit;
    size_t            max_list_len;
    VecComment        comments;
    VecGroupState     stack_group;
    VecClassState     stack_class;
    VecCaptureName    capture_names;
    n00b_buffer_t    *scratch;
    /* Per-parse allocator (forwarded from RegexBuilder).  When non-null,
     * every parser-internal allocation (AST nodes, helper lists, etc.)
     * routes through this allocator instead of the runtime default.
     * See gc-bits.md Step 5 / hidden-pool with side-list scanning. */
    n00b_allocator_t *allocator;
};

// ---------------------------------------------------------------------------
// PatternFlags
// ---------------------------------------------------------------------------

PatternFlags PatternFlags_default(void)
{
    return (PatternFlags){
        .unicode              = true,
        .full_unicode         = false,
        .case_insensitive     = false,
        .dot_matches_new_line = false,
        .multiline            = true,
        .ignore_whitespace    = false,
        .ascii_perl_classes   = false,
        .expanded_ast_limit   = DEFAULT_EXPANDED_AST_LIMIT,
        .max_list_len         = DEFAULT_MAX_LIST_LEN,
    };
}

// ---------------------------------------------------------------------------
// is_word_byte
// ---------------------------------------------------------------------------

static bool is_word_byte(uint8_t b)
{
    return char_is_ascii_alphanumeric((uint32_t)b) || b == (uint8_t)'_';
}

// ---------------------------------------------------------------------------
// Primitive::span / Primitive::into_ast
// ---------------------------------------------------------------------------

static const rs_Span *Primitive_span(const Primitive *p)
{
    switch (p->tag) {
        case PRIM_LITERAL:   return rs_Literal_span(&p->as.lit);
        case PRIM_ASSERTION: return &p->as.assertion.span;
        case PRIM_DOT:       return &p->as.span;
        case PRIM_TOP:       return &p->as.span;
        case PRIM_PERL:      return rs_ClassPerl_span(&p->as.perl);
        case PRIM_UNICODE:   return rs_ClassUnicode_span(&p->as.unicode);
    }
    n00b_unreachable();
}

static ast_Ast *Primitive_into_ast(Primitive p, n00b_allocator_t *allocator)
{
    switch (p.tag) {
        case PRIM_LITERAL:   return ast_Ast_literal_owned(p.as.lit, allocator);
        case PRIM_ASSERTION: return ast_Ast_assertion_owned(p.as.assertion, allocator);
        case PRIM_DOT:       return ast_Ast_dot_owned(p.as.span, allocator);
        case PRIM_TOP:       return ast_Ast_top_owned(p.as.span, allocator);
        case PRIM_PERL:      return ast_Ast_class_perl_owned(p.as.perl, allocator);
        case PRIM_UNICODE:   return ast_Ast_class_unicode_owned(p.as.unicode, allocator);
    }
    n00b_unreachable();
}

// ---------------------------------------------------------------------------
// Forward decls of parser internals used early.
// ---------------------------------------------------------------------------

static ParseError parser_error(const ResharpParser *p, rs_Span span,
                               ast_ErrorKind_tag tag);
static ParseError parser_error_with_span(const ResharpParser *p, rs_Span span,
                                         ast_ErrorKind_tag tag,
                                         rs_Span original);

// ---------------------------------------------------------------------------
// Primitive::into_class_set_item / into_class_literal
// ---------------------------------------------------------------------------

static bool Primitive_into_class_set_item(Primitive self, const ResharpParser *p,
                                          rs_ClassSetItem *out, ParseError *err)
{
    switch (self.tag) {
        case PRIM_LITERAL: *out = rs_ClassSetItem_literal(self.as.lit); return true;
        case PRIM_PERL:    *out = rs_ClassSetItem_perl(self.as.perl);   return true;
        case PRIM_UNICODE: *out = rs_ClassSetItem_unicode(self.as.unicode); return true;
        default: {
            const rs_Span *sp = Primitive_span(&self);
            *err = parser_error(p, *sp, AST_ERROR_KIND_CLASS_ESCAPE_INVALID);
            return false;
        }
    }
}

static bool Primitive_into_class_literal(Primitive self, const ResharpParser *p,
                                         rs_Literal *out, ParseError *err)
{
    if (self.tag == PRIM_LITERAL) { *out = self.as.lit; return true; }
    const rs_Span *sp = Primitive_span(&self);
    *err = parser_error(p, *sp, AST_ERROR_KIND_CLASS_RANGE_LITERAL);
    return false;
}

// ---------------------------------------------------------------------------
// ParseError helpers
// ---------------------------------------------------------------------------

static ParseError parser_error(const ResharpParser *p, rs_Span span,
                               ast_ErrorKind_tag tag)
{
    ParseError e;
    e.kind.tag      = tag;
    e.kind.original = (rs_Span){};
    size_t bytes = parser_ckd_add_sz(p->pattern_len, 1);
    char  *dup   = n00b_alloc_array(char, bytes);
    if (p->pattern_len > 0) memcpy(dup, p->pattern, p->pattern_len);
    dup[p->pattern_len] = '\0';
    e.pattern = dup;
    e.span    = span;
    return e;
}

static ParseError parser_error_with_span(const ResharpParser *p, rs_Span span,
                                         ast_ErrorKind_tag tag,
                                         rs_Span original)
{
    ParseError e = parser_error(p, span, tag);
    e.kind.original = original;
    return e;
}

void ParseError_free(ParseError *e)
{
    if (!e) return;
    if (e->pattern) n00b_free(e->pattern);
    e->pattern = nullptr;
}

// specialize_err: rewrite a ParseError if its kind matches `from`.
static bool specialize_err(bool ok, ParseError *err,
                           ast_ErrorKind_tag from, ast_ErrorKind_tag to)
{
    if (!ok && err->kind.tag == from) err->kind.tag = to;
    return ok;
}

// ---------------------------------------------------------------------------
// is_capture_char / parser_is_meta_character / parser_is_escapeable_character
// ---------------------------------------------------------------------------

static bool is_capture_char(uint32_t c, bool first)
{
    if (first) return c == '_' || char_is_alphabetic(c);
    return c == '_' || c == '.' || c == '[' || c == ']' || char_is_alphanumeric(c);
}

bool parser_is_meta_character(uint32_t c)
{
    switch (c) {
        case '\\': case '.': case '+': case '*': case '?':
        case '(':  case ')': case '|': case '[': case ']':
        case '{':  case '}': case '^': case '$': case '#':
        case '&':  case '-': case '~': case '_':
            return true;
        default:
            return false;
    }
}

bool parser_is_escapeable_character(uint32_t c)
{
    if (parser_is_meta_character(c)) return true;
    if (!char_is_ascii(c))           return false;
    if ((c >= '0' && c <= '9') ||
        (c >= 'A' && c <= 'Z') ||
        (c >= 'a' && c <= 'z')) return false;
    if (c == '<' || c == '>') return false;
    return true;
}

// ---------------------------------------------------------------------------
// parser_escape / parser_escape_into
// ---------------------------------------------------------------------------

void parser_escape_into(const char *text, char **buf,
                        size_t *buf_len, size_t *buf_cap)
{
    size_t in_len  = parser_strlen(text);
    size_t doubled = parser_ckd_mul_sz(in_len, 2);
    size_t need    = parser_ckd_add3_sz(*buf_len, doubled, 1);
    if (need > *buf_cap) {
        size_t cap = *buf_cap ? *buf_cap : 16;
        while (cap < need) cap = parser_ckd_mul_sz(cap, 2);
        char *fresh = n00b_alloc_array(char, cap);
        if (*buf && *buf_len > 0) memcpy(fresh, *buf, *buf_len);
        if (*buf) n00b_free(*buf);
        *buf     = fresh;
        *buf_cap = cap;
    }
    size_t i = 0;
    while (i < in_len) {
        size_t step;
        uint32_t c = utf8_decode_one(text + i, in_len - i, &step);
        if (step == 0) break;
        if (parser_is_meta_character(c)) {
            (*buf)[(*buf_len)++] = '\\';
        }
        for (size_t k = 0; k < step; k++) {
            (*buf)[(*buf_len)++] = text[i + k];
        }
        i += step;
    }
    (*buf)[*buf_len] = '\0';
}

char *parser_escape(const char *text)
{
    char  *buf = nullptr;
    size_t len = 0, cap = 0;
    parser_escape_into(text, &buf, &len, &cap);
    if (!buf) {
        buf    = n00b_alloc_array(char, 1);
        buf[0] = '\0';
    }
    return buf;
}

// ---------------------------------------------------------------------------
// ResharpParser construction
// ---------------------------------------------------------------------------

static rs_TranslatorBuilder
resharp_parser_default_translator_builder(const ResharpParser *p)
{
    rs_TranslatorBuilder trb = rs_TranslatorBuilder_new();
    rs_TranslatorBuilder_unicode(&trb, p->global_unicode);
    rs_TranslatorBuilder_utf8(&trb, false);
    rs_TranslatorBuilder_case_insensitive(&trb, p->global_case_insensitive);
    return trb;
}

static ResharpParser *resharp_parser_with_flags_alloc(const char *pattern,
                                                       const PatternFlags *flags,
                                                       n00b_allocator_t *allocator);

ResharpParser *resharp_parser_new(const char *pattern)
{
    PatternFlags flags = PatternFlags_default();
    return resharp_parser_with_flags_alloc(pattern, &flags, nullptr);
}

ResharpParser *resharp_parser_with_flags(const char *pattern,
                                         const PatternFlags *flags)
{
    return resharp_parser_with_flags_alloc(pattern, flags, nullptr);
}

static ResharpParser *resharp_parser_with_flags_alloc(const char *pattern,
                                                       const PatternFlags *flags,
                                                       n00b_allocator_t *allocator)
{
    ResharpParser *p = n00b_alloc_with_opts(
        ResharpParser, &(n00b_alloc_opts_t){.allocator = allocator});
    p->allocator    = allocator;
    rs_TranslatorBuilder trb = rs_TranslatorBuilder_new();
    rs_TranslatorBuilder_unicode(&trb, flags->unicode);
    rs_TranslatorBuilder_utf8(&trb, false);
    rs_TranslatorBuilder_case_insensitive(&trb, flags->case_insensitive);
    p->translator   = rs_TranslatorBuilder_build(&trb);
    p->pattern      = pattern;
    p->pattern_len  = parser_strlen(pattern);
    p->perl_classes = n00b_list_new_private(PerlClassEntry, .allocator = allocator);
    p->unicode_classes        = UnicodeClassCache_default();
    p->pos                    = rs_Position_new(0, 0, 0);
    p->capture_index          = 0;
    p->octal                  = false;
    p->empty_min_range        = false;
    p->ignore_whitespace      = flags->ignore_whitespace;
    p->dot_all                = flags->dot_matches_new_line;
    p->multiline              = flags->multiline;
    p->global_unicode         = flags->unicode || flags->full_unicode
                              || flags->ascii_perl_classes;
    p->global_full_unicode    = flags->full_unicode;
    p->global_ascii_perl      = flags->ascii_perl_classes;
    p->global_case_insensitive = flags->case_insensitive;
    p->expanded_ast_limit     = flags->expanded_ast_limit;
    p->max_list_len           = flags->max_list_len;
    p->comments      = n00b_list_new_private(ast_Comment, .allocator = allocator);
    p->stack_group   = n00b_list_new_private(GroupState, .allocator = allocator);
    p->stack_class   = n00b_list_new_private(ClassState, .allocator = allocator);
    p->capture_names = n00b_list_new_private(ast_CaptureName, .allocator = allocator);
    p->scratch       = parser_scratch_new();
    return p;
}

void resharp_parser_free(ResharpParser *p)
{
    if (!p) return;
    rs_Translator_free(&p->translator);
    n00b_list_free(p->perl_classes);
    // UnicodeClassCache: NodeIds are owned by the RegexBuilder, no field
    // teardown needed.
    n00b_list_free(p->comments);
    n00b_list_free(p->stack_group);
    n00b_list_free(p->stack_class);
    n00b_list_free(p->capture_names);
    n00b_buffer_free(p->scratch);
    n00b_free(p);
}

// ---------------------------------------------------------------------------
// Position-related accessors
// ---------------------------------------------------------------------------

[[maybe_unused]]
static const char *parser_pattern(const ResharpParser *p) { return p->pattern; }
static size_t      parser_offset (const ResharpParser *p) { return p->pos.offset; }
static size_t      parser_line   (const ResharpParser *p) { return p->pos.line; }
static size_t      parser_column (const ResharpParser *p) { return p->pos.column; }
static rs_Position parser_pos    (const ResharpParser *p) { return p->pos; }

static rs_Span parser_span(const ResharpParser *p)
{
    return rs_Span_splat(p->pos);
}

static bool parser_is_eof(const ResharpParser *p)
{
    return parser_offset(p) == p->pattern_len;
}

static uint32_t parser_char_at(const ResharpParser *p, size_t i)
{
    n00b_require(i < p->pattern_len,
                 "parser_char_at: offset past pattern_len");
    size_t step;
    return utf8_decode_one(p->pattern + i, p->pattern_len - i, &step);
}

static uint32_t parser_char(const ResharpParser *p)
{
    return parser_char_at(p, parser_offset(p));
}

static bool parser_peek(const ResharpParser *p, uint32_t *out)
{
    if (parser_is_eof(p)) return false;
    size_t cur_step;
    (void)utf8_decode_one(p->pattern + parser_offset(p),
                          p->pattern_len - parser_offset(p), &cur_step);
    if (cur_step == 0) return false;
    size_t off = parser_offset(p) + cur_step;
    if (off >= p->pattern_len) return false;
    size_t s2;
    *out = utf8_decode_one(p->pattern + off, p->pattern_len - off, &s2);
    return s2 != 0;
}

static bool parser_ignore_whitespace(const ResharpParser *p)
{
    return p->ignore_whitespace;
}

static bool parser_bump(ResharpParser *p)
{
    if (parser_is_eof(p)) return false;
    rs_Position pos    = p->pos;
    size_t      offset = pos.offset;
    size_t      line   = pos.line;
    size_t      column = pos.column;
    size_t      cur_step;
    uint32_t    c = utf8_decode_one(p->pattern + offset,
                                    p->pattern_len - offset, &cur_step);
    if (cur_step == 0) {
        // The parser_is_eof() guard above excludes the only path to step==0;
        // surface invariant violations loudly.
        n00b_unreachable();
    }
    if (c == '\n') { line += 1; column = 1; }
    else           { column += 1; }
    offset += cur_step;
    p->pos = (rs_Position){.offset = offset, .line = line, .column = column};
    if (offset >= p->pattern_len) return false;
    size_t step;
    (void)utf8_decode_one(p->pattern + offset, p->pattern_len - offset, &step);
    return step != 0;
}

static bool parser_bump_if(ResharpParser *p, const char *prefix)
{
    size_t pl = parser_strlen(prefix);
    if (parser_offset(p) + pl > p->pattern_len) return false;
    if (memcmp(p->pattern + parser_offset(p), prefix, pl) != 0) return false;
    size_t i = 0;
    while (i < pl) {
        size_t step;
        (void)utf8_decode_one(prefix + i, pl - i, &step);
        if (step == 0) break;
        parser_bump(p);
        i += step;
    }
    return true;
}

static int parser_is_lookaround_prefix(ResharpParser *p, bool *ahead, bool *pos_)
{
    if (parser_bump_if(p, "?="))  { *ahead = true;  *pos_ = true;  return 1; }
    if (parser_bump_if(p, "?!"))  { *ahead = true;  *pos_ = false; return 1; }
    if (parser_bump_if(p, "?<=")) { *ahead = false; *pos_ = true;  return 1; }
    if (parser_bump_if(p, "?<!")) { *ahead = false; *pos_ = false; return 1; }
    return 0;
}

static void parser_bump_space(ResharpParser *p);

static bool parser_bump_and_bump_space(ResharpParser *p)
{
    if (!parser_bump(p)) return false;
    parser_bump_space(p);
    return !parser_is_eof(p);
}

static void parser_bump_space(ResharpParser *p)
{
    if (!parser_ignore_whitespace(p)) return;
    while (!parser_is_eof(p)) {
        uint32_t c = parser_char(p);
        if (char_is_whitespace(c)) {
            parser_bump(p);
        } else if (c == '#') {
            rs_Position    start        = parser_pos(p);
            n00b_buffer_t *comment_text = parser_scratch_new();
            parser_bump(p);
            while (!parser_is_eof(p)) {
                uint32_t cc = parser_char(p);
                parser_bump(p);
                if (cc == '\n') break;
                parser_scratch_push_char(comment_text, cc);
            }
            ast_Comment comment = {};
            comment.span = rs_Span_new(start, parser_pos(p));
            ast_Comment_set_text(&comment, parser_scratch_dup_cstr(comment_text));
            n00b_list_push(p->comments, comment);
            n00b_buffer_free(comment_text);
        } else {
            break;
        }
    }
}

static bool parser_peek_space(const ResharpParser *p, uint32_t *out)
{
    if (!parser_ignore_whitespace(p)) {
        if (parser_is_eof(p)) return false;
        size_t cur_step;
        (void)utf8_decode_one(p->pattern + parser_offset(p),
                              p->pattern_len - parser_offset(p), &cur_step);
        if (cur_step == 0) return false;
        size_t off = parser_offset(p) + cur_step;
        if (off >= p->pattern_len) return false;
        size_t s2;
        *out = utf8_decode_one(p->pattern + off, p->pattern_len - off, &s2);
        return s2 != 0;
    }
    if (parser_is_eof(p)) return false;
    size_t cur_step;
    (void)utf8_decode_one(p->pattern + parser_offset(p),
                          p->pattern_len - parser_offset(p), &cur_step);
    if (cur_step == 0) return false;
    size_t start      = parser_offset(p) + cur_step;
    bool   in_comment = false;
    size_t i          = 0;
    while (start + i < p->pattern_len) {
        size_t step;
        uint32_t c = utf8_decode_one(p->pattern + start + i,
                                     p->pattern_len - start - i, &step);
        if (step == 0) break;
        if (char_is_whitespace(c)) {
            i += step;
            continue;
        } else if (!in_comment && c == '#') {
            in_comment = true;  i += step;
        } else if (in_comment && c == '\n') {
            in_comment = false; i += step;
        } else if (in_comment) {
            i += step;
        } else {
            break;
        }
    }
    if (start + i >= p->pattern_len) return false;
    size_t s2;
    *out = utf8_decode_one(p->pattern + start + i,
                           p->pattern_len - start - i, &s2);
    return s2 != 0;
}

static rs_Span parser_span_char(const ResharpParser *p)
{
    size_t   cur_step;
    uint32_t c = utf8_decode_one(p->pattern + parser_offset(p),
                                 p->pattern_len - parser_offset(p), &cur_step);
    if (cur_step == 0) {
        n00b_unreachable();
    }
    rs_Position next;
    next.offset = parser_offset(p) + cur_step;
    next.line   = parser_line(p);
    next.column = parser_column(p) + 1;
    if (c == '\n') { next.line += 1; next.column = 1; }
    return rs_Span_new(parser_pos(p), next);
}

// ---------------------------------------------------------------------------
// next_capture_index / add_capture_name
// ---------------------------------------------------------------------------

static bool parser_next_capture_index(ResharpParser *p, rs_Span span,
                                      uint32_t *out, ParseError *err)
{
    uint32_t cur = p->capture_index;
    if (cur == UINT32_MAX) {
        *err = parser_error(p, span, AST_ERROR_KIND_CAPTURE_LIMIT_EXCEEDED);
        return false;
    }
    p->capture_index = cur + 1;
    *out             = cur + 1;
    return true;
}

static bool parser_add_capture_name(ResharpParser *p, const ast_CaptureName *cap,
                                    ParseError *err)
{
    const char *cname = ast_CaptureName_name(cap);
    size_t lo = 0, hi = p->capture_names.len;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const char *mname = ast_CaptureName_name(&p->capture_names.data[mid]);
        int cmp = parser_strcmp(mname, cname);
        if (cmp < 0) {
            lo = mid + 1;
        } else if (cmp > 0) {
            hi = mid;
        } else {
            *err = parser_error_with_span(
                p, ast_CaptureName_span(cap),
                AST_ERROR_KIND_GROUP_NAME_DUPLICATE,
                ast_CaptureName_span(&p->capture_names.data[mid]));
            return false;
        }
    }
    // Single-owner transfer of *cap into the list slot at `lo`.
    // Ownership of the heap-owned `name` field moves into the list;
    // the duplicate-rejection path above must NOT be reached when the
    // caller transferred ownership.  n00b_list_insert handles the
    // capacity grow + memmove + assign + len++ sequence.
    n00b_list_insert(p->capture_names, lo, *cap);
    return true;
}

// ---------------------------------------------------------------------------
// Drop helpers — release in-flight ast_Concat / Alternation / Intersection
// (and every owned child) on parse-error paths.
// ---------------------------------------------------------------------------

static ast_Ast *concat_into_ast_owned(ast_Concat c, n00b_allocator_t *allocator)
{
    return ast_Concat_into_ast_owned(c, allocator);
}

static ast_Ast *alternation_into_ast_owned(ast_Alternation a,
                                            n00b_allocator_t *allocator)
{
    return ast_Alternation_into_ast_owned(a, allocator);
}

static ast_Ast *intersection_into_ast_owned(ast_Intersection a,
                                              n00b_allocator_t *allocator)
{
    return ast_Intersection_into_ast_owned(a, allocator);
}

static void parser_drop_in_flight_concat(ast_Concat c,
                                          n00b_allocator_t *allocator)
{
    ast_Ast_free(concat_into_ast_owned(c, allocator));
}

// ---------------------------------------------------------------------------
// push_alternate / push_or_add_alternation / push_intersect (forward)
// ---------------------------------------------------------------------------

static void parser_push_or_add_alternation(ResharpParser *p, ast_Concat concat)
{
    if (p->stack_group.len > 0) {
        GroupState *top = &p->stack_group.data[p->stack_group.len - 1];
        if (n00b_variant_is_type(*top, ast_Alternation)) {
            ast_Alternation _alt = n00b_variant_get(*top, ast_Alternation);
            ast_Alternation_push_ast(&_alt,
                                     concat_into_ast_owned(concat, p->allocator), p->allocator);
            *top = n00b_variant_set(GroupState, ast_Alternation, _alt);
            return;
        }
    }
    rs_Span span = rs_Span_new(ast_Concat_span_start(&concat), parser_pos(p));
    ast_Alternation alt = ast_Alternation_new(span);
    ast_Alternation_push_ast(&alt, concat_into_ast_owned(concat, p->allocator), p->allocator);
    GroupState gs = n00b_variant_set(GroupState, ast_Alternation, alt);
    n00b_list_push(p->stack_group, gs);
}

static bool parser_push_intersect(ResharpParser *p, ast_Concat concat,
                                  ast_Concat *out, ParseError *err);

static bool parser_push_alternate(ResharpParser *p, ast_Concat concat,
                                  ast_Concat *out, ParseError *err)
{
    (void)err;
    n00b_require(parser_char(p) == '|',
                 "parser_push_alternate: expected '|'");
    ast_Concat_set_span_end(&concat, parser_pos(p));
    parser_push_or_add_alternation(p, concat);
    parser_bump(p);
    *out = ast_Concat_new(parser_span(p));
    return true;
}

// ---------------------------------------------------------------------------
// push_group / parse_group / push_compl_group
// ---------------------------------------------------------------------------

typedef struct ParseGroupResult {
    Either_tag   tag;
    ast_SetFlags set_flags;   // EITHER_LEFT
    ast_Group    group;       // EITHER_RIGHT
} ParseGroupResult;

static bool parser_parse_group(ResharpParser *p, ParseGroupResult *out,
                               ParseError *err);

static bool parser_push_group(ResharpParser *p, ast_Concat concat,
                              ast_Concat *out, ParseError *err)
{
    n00b_require(parser_char(p) == '(',
                 "parser_push_group: expected '('");
    ParseGroupResult res;
    if (!parser_parse_group(p, &res, err)) {
        parser_drop_in_flight_concat(concat, p->allocator);
        return false;
    }
    if (res.tag == EITHER_LEFT) {
        int v = ast_SetFlags_flag_state(&res.set_flags, AST_FLAG_IGNORE_WHITESPACE);
        if (v >= 0) p->ignore_whitespace = (v != 0);
        ast_Concat_push_ast(&concat, ast_Ast_flags_owned(res.set_flags, p->allocator), p->allocator);
        *out = concat;
        return true;
    }
    bool old_iw = p->ignore_whitespace;
    const ast_Flags *gflags = ast_Group_flags(&res.group);
    bool new_iw = old_iw;
    if (gflags) {
        int v = ast_Flags_flag_state(gflags, AST_FLAG_IGNORE_WHITESPACE);
        if (v >= 0) new_iw = (v != 0);
    }
    GroupState gs = n00b_variant_set(GroupState, GroupState_group_t,
                                     ((GroupState_group_t){
                                         .concat            = concat,
                                         .group             = res.group,
                                         .ignore_whitespace = old_iw,
                                     }));
    n00b_list_push(p->stack_group, gs);
    p->ignore_whitespace = new_iw;
    *out = ast_Concat_new(parser_span(p));
    return true;
}

static bool parser_push_compl_group(ResharpParser *p, ast_Concat concat,
                                    ast_Concat *out, ParseError *err)
{
    n00b_require(parser_char(p) == '~',
                 "parser_push_compl_group: expected '~'");
    parser_bump(p);
    if (parser_is_eof(p) || parser_char(p) != '(') {
        *err = parser_error(p, parser_span(p),
                            AST_ERROR_KIND_COMPLEMENT_GROUP_EXPECTED);
        parser_drop_in_flight_concat(concat, p->allocator);
        return false;
    }
    rs_Span open_span = parser_span_char(p);
    parser_bump(p);
    ast_Group group = ast_Group_new_complement(open_span, parser_span(p));

    bool old_iw = p->ignore_whitespace;
    const ast_Flags *gflags = ast_Group_flags(&group);
    bool new_iw = old_iw;
    if (gflags) {
        int v = ast_Flags_flag_state(gflags, AST_FLAG_IGNORE_WHITESPACE);
        if (v >= 0) new_iw = (v != 0);
    }
    GroupState gs = n00b_variant_set(GroupState, GroupState_group_t,
                                     ((GroupState_group_t){
                                         .concat            = concat,
                                         .group             = group,
                                         .ignore_whitespace = old_iw,
                                     }));
    n00b_list_push(p->stack_group, gs);
    p->ignore_whitespace = new_iw;
    *out = ast_Concat_new(parser_span(p));
    return true;
}

// ---------------------------------------------------------------------------
// pop_group
// ---------------------------------------------------------------------------

static bool parser_pop_group(ResharpParser *p, ast_Concat group_concat,
                             ast_Concat *out, ParseError *err)
{
    n00b_require(parser_char(p) == ')',
                 "parser_pop_group: expected ')'");

    n00b_option_t(GroupState) top_opt = n00b_list_pop(GroupState, p->stack_group);
    if (!n00b_option_is_set(top_opt)) {
        *err = parser_error(p, parser_span_char(p),
                            AST_ERROR_KIND_GROUP_UNOPENED);
        parser_drop_in_flight_concat(group_concat, p->allocator);
        return false;
    }
    GroupState top = n00b_option_get(top_opt);

    ast_Concat       prior_concat;
    ast_Group        group;
    bool             ignore_ws;
    bool             have_alt    = false;
    bool             alt_is_left = false;
    ast_Alternation  alt_alt     = {};
    ast_Intersection alt_int     = {};

    if (n00b_variant_is_type(top, GroupState_group_t)) {
        GroupState_group_t _g = n00b_variant_get(top, GroupState_group_t);
        prior_concat = _g.concat;
        group        = _g.group;
        ignore_ws    = _g.ignore_whitespace;
    } else if (n00b_variant_is_type(top, ast_Alternation)) {
        ast_Alternation alt = n00b_variant_get(top, ast_Alternation);
        n00b_option_t(GroupState) below_opt =
            n00b_list_pop(GroupState, p->stack_group);
        GroupState below;
        if (!n00b_option_is_set(below_opt)
            || (below = n00b_option_get(below_opt),
                !n00b_variant_is_type(below, GroupState_group_t))) {
            *err = parser_error(p, parser_span_char(p),
                                AST_ERROR_KIND_GROUP_UNOPENED);
            parser_drop_in_flight_concat(group_concat, p->allocator);
            ast_Ast_free(alternation_into_ast_owned(alt, p->allocator));
            return false;
        }
        GroupState_group_t _b = n00b_variant_get(below, GroupState_group_t);
        prior_concat = _b.concat;
        group        = _b.group;
        ignore_ws    = _b.ignore_whitespace;
        have_alt = true; alt_is_left = true; alt_alt = alt;
    } else {
        ast_Intersection inter = n00b_variant_get(top, ast_Intersection);
        n00b_option_t(GroupState) below_opt =
            n00b_list_pop(GroupState, p->stack_group);
        GroupState below;
        if (!n00b_option_is_set(below_opt)
            || (below = n00b_option_get(below_opt),
                !n00b_variant_is_type(below, GroupState_group_t))) {
            *err = parser_error(p, parser_span_char(p),
                                AST_ERROR_KIND_GROUP_UNOPENED);
            parser_drop_in_flight_concat(group_concat, p->allocator);
            ast_Ast_free(intersection_into_ast_owned(inter, p->allocator));
            return false;
        }
        GroupState_group_t _b = n00b_variant_get(below, GroupState_group_t);
        prior_concat = _b.concat;
        group        = _b.group;
        ignore_ws    = _b.ignore_whitespace;
        have_alt = true; alt_is_left = false; alt_int = inter;
    }

    p->ignore_whitespace = ignore_ws;
    ast_Concat_set_span_end(&group_concat, parser_pos(p));
    parser_bump(p);
    ast_Group_set_span_end(&group, parser_pos(p));

    if (have_alt && alt_is_left) {
        ast_Alternation_set_span_end(&alt_alt, ast_Concat_span_end(&group_concat));
        ast_Alternation_push_ast(&alt_alt, concat_into_ast_owned(group_concat, p->allocator), p->allocator);
        ast_Group_set_ast(&group, alternation_into_ast_owned(alt_alt, p->allocator));
    } else if (have_alt) {
        ast_Intersection_set_span_end(&alt_int, ast_Concat_span_end(&group_concat));
        ast_Intersection_push_ast(&alt_int, concat_into_ast_owned(group_concat, p->allocator), p->allocator);
        ast_Group_set_ast(&group, intersection_into_ast_owned(alt_int, p->allocator));
    } else {
        ast_Group_set_ast(&group, concat_into_ast_owned(group_concat, p->allocator));
    }

    if (ast_Group_kind_is_complement(&group)) {
        ast_Complement compl_ = ast_Complement_new(parser_span(p),
                                                   ast_Group_take_ast(&group));
        ast_Concat_push_ast(&prior_concat, ast_Ast_complement_owned(compl_, p->allocator), p->allocator);
    } else {
        ast_Concat_push_ast(&prior_concat, ast_Ast_group_owned(group, p->allocator), p->allocator);
    }
    *out = prior_concat;
    return true;
}

// ---------------------------------------------------------------------------
// pop_group_end
// ---------------------------------------------------------------------------

static bool parser_pop_group_end(ResharpParser *p, ast_Concat concat,
                                 ast_Ast **out, ParseError *err)
{
    ast_Concat_set_span_end(&concat, parser_pos(p));
    n00b_option_t(GroupState) top_opt =
        n00b_list_pop(GroupState, p->stack_group);
    GroupState top;
    if (!n00b_option_is_set(top_opt)) {
        *out = concat_into_ast_owned(concat, p->allocator);
    } else if ((top = n00b_option_get(top_opt),
                n00b_variant_is_type(top, ast_Alternation))) {
        ast_Alternation alt = n00b_variant_get(top, ast_Alternation);
        ast_Alternation_set_span_end(&alt, parser_pos(p));
        ast_Alternation_push_ast(&alt, concat_into_ast_owned(concat, p->allocator), p->allocator);
        *out = ast_Ast_alternation_owned(alt, p->allocator);
    } else if (n00b_variant_is_type(top, ast_Intersection)) {
        ast_Intersection inter = n00b_variant_get(top, ast_Intersection);
        ast_Intersection_set_span_end(&inter, parser_pos(p));
        ast_Intersection_push_ast(&inter, concat_into_ast_owned(concat, p->allocator), p->allocator);
        *out = ast_Ast_intersection_owned(inter, p->allocator);
    } else {
        parser_drop_in_flight_concat(concat, p->allocator);
        GroupState_group_t _g = n00b_variant_get(top, GroupState_group_t);
        *err = parser_error(p, ast_Group_span(&_g.group),
                            AST_ERROR_KIND_GROUP_UNCLOSED);
        return false;
    }
    n00b_option_t(GroupState) extra_opt =
        n00b_list_pop(GroupState, p->stack_group);
    if (!n00b_option_is_set(extra_opt)) return true;
    top = n00b_option_get(extra_opt);
    ast_Ast_free(*out);
    *out = nullptr;
    if (n00b_variant_is_type(top, ast_Alternation)) {
        ast_Alternation _alt = n00b_variant_get(top, ast_Alternation);
        *err = parser_error(p, ast_Alternation_span(&_alt),
                            AST_ERROR_KIND_UNSUPPORTED_RESHARP_REGEX);
    } else if (n00b_variant_is_type(top, ast_Intersection)) {
        ast_Intersection _inter = n00b_variant_get(top, ast_Intersection);
        *err = parser_error(p, ast_Intersection_span(&_inter),
                            AST_ERROR_KIND_UNSUPPORTED_RESHARP_REGEX);
    } else {
        GroupState_group_t _g = n00b_variant_get(top, GroupState_group_t);
        *err = parser_error(p, ast_Group_span(&_g.group),
                            AST_ERROR_KIND_GROUP_UNCLOSED);
    }
    return false;
}

// ---------------------------------------------------------------------------
// Class-bracketed support: push_class_open, pop_class, push_class_op,
// pop_class_op, unclosed_class_error.
// ---------------------------------------------------------------------------

static bool parser_parse_set_class_open(ResharpParser *p,
                                        rs_ClassBracketed *out_set,
                                        rs_ClassSetUnion *out_union,
                                        ParseError *err);

static bool parser_push_class_open(ResharpParser *p,
                                   rs_ClassSetUnion parent_union,
                                   rs_ClassSetUnion *out_union,
                                   ParseError *err)
{
    n00b_require(parser_char(p) == '[',
                 "parser_push_class_open: expected '['");
    rs_ClassBracketed nested_set;
    rs_ClassSetUnion  nested_union;
    if (!parser_parse_set_class_open(p, &nested_set, &nested_union, err)) {
        return false;
    }
    ClassState cs = n00b_variant_set(ClassState, ClassState_open_t,
                                     ((ClassState_open_t){
                                         .union_ = parent_union,
                                         .set    = nested_set,
                                     }));
    n00b_list_push(p->stack_class, cs);
    *out_union = nested_union;
    return true;
}

static rs_ClassSet parser_pop_class_op(ResharpParser *p, rs_ClassSet rhs)
{
    n00b_option_t(ClassState) top_opt =
        n00b_list_pop(ClassState, p->stack_class);
    if (!n00b_option_is_set(top_opt)) {
        n00b_panic("pop_class_op: stack empty (Rust unreachable!)");
    }
    ClassState top = n00b_option_get(top_opt);
    if (n00b_variant_is_type(top, ClassState_open_t)) {
        n00b_list_push(p->stack_class, top);
        return rhs;
    }
    ClassState_op_t _op = n00b_variant_get(top, ClassState_op_t);
    rs_ClassSetBinaryOpKind kind = _op.kind;
    rs_ClassSet             lhs  = _op.lhs;
    rs_Span span = rs_Span_combine(rs_ClassSet_span(&lhs).start,
                                   rs_ClassSet_span(&rhs).end);
    return rs_ClassSet_binary_op(kind, lhs, rhs, span);
}

typedef struct PopClassResult {
    Either_tag        tag;
    rs_ClassSetUnion  left;
    rs_ClassBracketed right;
} PopClassResult;

static bool parser_pop_class(ResharpParser *p, rs_ClassSetUnion nested_union,
                             PopClassResult *out, ParseError *err)
{
    (void)err;
    n00b_require(parser_char(p) == ']',
                 "parser_pop_class: expected ']'");
    rs_ClassSetItem item    = rs_ClassSetUnion_into_item(nested_union);
    rs_ClassSet     prevset = parser_pop_class_op(p, rs_ClassSet_item(item));
    n00b_option_t(ClassState) top_opt =
        n00b_list_pop(ClassState, p->stack_class);
    if (!n00b_option_is_set(top_opt)) {
        n00b_panic("parser_pop_class: empty class stack");
    }
    ClassState top = n00b_option_get(top_opt);
    if (n00b_variant_is_type(top, ClassState_op_t)) {
        n00b_panic("parser_pop_class: unexpected ClassState::Op (Rust unreachable!)");
    }
    ClassState_open_t _open = n00b_variant_get(top, ClassState_open_t);
    rs_ClassSetUnion  union_ = _open.union_;
    rs_ClassBracketed set    = _open.set;
    parser_bump(p);
    rs_ClassBracketed_set_span_end(&set, parser_pos(p));
    rs_ClassBracketed_set_kind(&set, prevset);
    if (p->stack_class.len == 0) {
        out->tag   = EITHER_RIGHT;
        out->right = set;
    } else {
        rs_ClassSetUnion_push(&union_, rs_ClassSetItem_bracketed(set));
        out->tag  = EITHER_LEFT;
        out->left = union_;
    }
    return true;
}

static ParseError parser_unclosed_class_error(const ResharpParser *p)
{
    for (size_t i = p->stack_class.len; i > 0; i--) {
        const ClassState *s = &p->stack_class.data[i - 1];
        if (n00b_variant_is_type(*s, ClassState_open_t)) {
            ClassState_open_t _open = n00b_variant_get(*s, ClassState_open_t);
            return parser_error(p, rs_ClassBracketed_span(&_open.set),
                                AST_ERROR_KIND_CLASS_UNCLOSED);
        }
    }
    n00b_panic("parser_unclosed_class_error: no open character class on stack");
}

static rs_ClassSetUnion parser_push_class_op(ResharpParser *p,
                                             rs_ClassSetBinaryOpKind next_kind,
                                             rs_ClassSetUnion next_union)
{
    rs_ClassSetItem item    = rs_ClassSetUnion_into_item(next_union);
    rs_ClassSet     new_lhs = parser_pop_class_op(p, rs_ClassSet_item(item));
    ClassState cs = n00b_variant_set(ClassState, ClassState_op_t,
                                     ((ClassState_op_t){
                                         .kind = next_kind,
                                         .lhs  = new_lhs,
                                     }));
    n00b_list_push(p->stack_class, cs);
    return rs_ClassSetUnion_new(parser_span(p));
}

// ---------------------------------------------------------------------------
// hir_to_node_id
// ---------------------------------------------------------------------------

// Local enums for rs_Hir kind / class tag.  The implementations live in
// regex_syntax.c (Phase 6 sibling), with ABI-compatible enums.
typedef enum {
    RS_HIR_EMPTY,
    RS_HIR_LITERAL,
    RS_HIR_CLASS,
    RS_HIR_LOOK,
    RS_HIR_REPETITION,
    RS_HIR_CAPTURE,
    RS_HIR_CONCAT,
    RS_HIR_ALTERNATION,
} rs_HirKindTag;

typedef enum {
    RS_HIR_CLASS_UNICODE,
    RS_HIR_CLASS_BYTES,
} rs_HirClassTag;

extern rs_HirKindTag rs_Hir_kind(const rs_Hir *h);
extern rs_HirClassTag rs_Hir_class_tag(const rs_Hir *h);

static bool parser_hir_to_node_id(ResharpParser *p, const rs_Hir *h,
                                  RegexBuilder *tb,
                                  NodeId *out, ParseError *err)
{
    rs_HirKindTag k = rs_Hir_kind(h);
    switch (k) {
        case RS_HIR_EMPTY: *out = NODE_ID_EPS; return true;
        case RS_HIR_LITERAL: {
            size_t n;
            const uint8_t *bytes = rs_Hir_literal_bytes(h, &n);
            if (n == 1) {
                *out = regex_builder_mk_u8(tb, bytes[0]);
            } else {
                size_t bytesz = parser_ckd_mul_sz(n, sizeof(NodeId));
                (void)bytesz;
                NodeId *ws = n00b_alloc_array_with_opts(NodeId, n,
                    &(n00b_alloc_opts_t){.allocator = p->allocator,
                                          .scan_kind = N00B_GC_SCAN_KIND_NONE});
                for (size_t i = 0; i < n; i++) {
                    ws[i] = regex_builder_mk_u8(tb, bytes[i]);
                }
                *out = regex_builder_mk_concats(tb, ws, n);
                n00b_free(ws);
            }
            return true;
        }
        case RS_HIR_CLASS: {
            rs_HirClassTag ct = rs_Hir_class_tag(h);
            if (ct == RS_HIR_CLASS_UNICODE) {
                size_t cnt = rs_Hir_class_unicode_ranges(h, nullptr, nullptr, 0);
                size_t bytesz = parser_ckd_mul_sz(cnt, sizeof(uint32_t));
                (void)bytesz;
                uint32_t *starts = n00b_alloc_array_with_opts(uint32_t, cnt,
                    &(n00b_alloc_opts_t){.allocator = p->allocator,
                                          .scan_kind = N00B_GC_SCAN_KIND_NONE});
                uint32_t *ends   = n00b_alloc_array_with_opts(uint32_t, cnt,
                    &(n00b_alloc_opts_t){.allocator = p->allocator,
                                          .scan_kind = N00B_GC_SCAN_KIND_NONE});
                rs_Hir_class_unicode_ranges(h, starts, ends, cnt);
                if (cnt == 1 && starts[0] == 0u && ends[0] == 0x10FFFFu) {
                    n00b_free(starts); n00b_free(ends);
                    *out = regex_builder_mk_range_u8(tb, 0, 255);
                    return true;
                }
                VecNodeId nodes = n00b_list_new_private(NodeId, .scan_kind = N00B_GC_SCAN_KIND_NONE, .allocator = p->allocator);
                for (size_t r = 0; r < cnt; r++) {
                    rs_Utf8Sequences *it = rs_Utf8Sequences_new(starts[r], ends[r]);
                    rs_Utf8Range bufseq[8];
                    size_t nseq;
                    while (rs_Utf8Sequences_next(it, bufseq, &nseq)) {
                        NodeId node;
                        if (nseq == 1) {
                            node = regex_builder_mk_range_u8(tb, bufseq[0].start, bufseq[0].end);
                        } else {
                            NodeId last = regex_builder_mk_range_u8(
                                tb, bufseq[nseq - 1].start, bufseq[nseq - 1].end);
                            NodeId conc = last;
                            for (ssize_t i = (ssize_t)nseq - 2; i >= 0; i--) {
                                NodeId b = regex_builder_mk_range_u8(
                                    tb, bufseq[i].start, bufseq[i].end);
                                conc = regex_builder_mk_concat(tb, b, conc);
                            }
                            node = conc;
                        }
                        n00b_list_push(nodes, node);
                    }
                    rs_Utf8Sequences_free(it);
                }
                n00b_free(starts); n00b_free(ends);
                *out = regex_builder_mk_unions(tb, nodes.data, nodes.len);
                n00b_list_free(nodes);
                return true;
            } else {
                size_t cnt = rs_Hir_class_bytes_ranges(h, nullptr, nullptr, 0);
                uint8_t *starts = n00b_alloc_array_with_opts(uint8_t, cnt,
                    &(n00b_alloc_opts_t){.allocator = p->allocator,
                                          .scan_kind = N00B_GC_SCAN_KIND_NONE});
                uint8_t *ends   = n00b_alloc_array_with_opts(uint8_t, cnt,
                    &(n00b_alloc_opts_t){.allocator = p->allocator,
                                          .scan_kind = N00B_GC_SCAN_KIND_NONE});
                rs_Hir_class_bytes_ranges(h, starts, ends, cnt);
                NodeId result = NODE_ID_BOT;
                for (size_t r = 0; r < cnt; r++) {
                    NodeId node = regex_builder_mk_range_u8(tb, starts[r], ends[r]);
                    result = regex_builder_mk_union(tb, result, node);
                }
                n00b_free(starts); n00b_free(ends);
                *out = result;
                return true;
            }
        }
        case RS_HIR_LOOK:
        case RS_HIR_REPETITION:
        case RS_HIR_CAPTURE:
        case RS_HIR_ALTERNATION:
            *err = parser_error(p, rs_Span_splat(parser_pos(p)),
                                AST_ERROR_KIND_UNSUPPORTED_RESHARP_REGEX);
            return false;
        case RS_HIR_CONCAT: {
            size_t n = rs_Hir_concat_count(h);
            NodeId result = NODE_ID_EPS;
            for (size_t i = 0; i < n; i++) {
                const rs_Hir *child = rs_Hir_concat_child(h, i);
                NodeId node;
                if (!parser_hir_to_node_id(p, child, tb, &node, err)) return false;
                result = regex_builder_mk_concat(tb, result, node);
            }
            *out = result;
            return true;
        }
    }
    *err = parser_error(p, parser_span(p), AST_ERROR_KIND_UNSUPPORTED_RESHARP_REGEX);
    return false;
}

// ---------------------------------------------------------------------------
// translate_ast_to_hir / translator_to_node_id
// ---------------------------------------------------------------------------

static bool parser_translate_ast_to_hir(ResharpParser *p,
                                        const rs_Ast *orig_ast,
                                        RegexBuilder *tb,
                                        NodeId *out,
                                        ParseError *err)
{
    rs_Hir *hir = nullptr;
    if (!rs_Translator_translate(&p->translator, "", orig_ast, &hir)) {
        *err = parser_error(p, parser_span(p),
                            AST_ERROR_KIND_UNICODE_CLASS_INVALID);
        return false;
    }
    bool ok = parser_hir_to_node_id(p, hir, tb, out, err);
    rs_Hir_free(hir);
    return ok;
}

static bool parser_translator_to_node_id(ResharpParser *p,
                                         const rs_Ast *orig_ast,
                                         rs_Translator *opt_tr,
                                         RegexBuilder *tb,
                                         NodeId *out,
                                         ParseError *err)
{
    if (opt_tr) {
        rs_Hir *hir = nullptr;
        if (!rs_Translator_translate(opt_tr, "", orig_ast, &hir)) {
            *err = parser_error(p, rs_Span_splat(parser_pos(p)),
                                AST_ERROR_KIND_UNSUPPORTED_RESHARP_REGEX);
            return false;
        }
        bool ok = parser_hir_to_node_id(p, hir, tb, out, err);
        rs_Hir_free(hir);
        return ok;
    }
    return parser_translate_ast_to_hir(p, orig_ast, tb, out, err);
}

// ---------------------------------------------------------------------------
// get_class — perl class lookup/translation with memoization.
// ---------------------------------------------------------------------------

static bool parser_get_class(ResharpParser *p, bool negated,
                             rs_ClassPerlKind kind,
                             RegexBuilder *tb,
                             NodeId *out, ParseError *err)
{
    (void)err;
    for (size_t i = 0; i < p->perl_classes.len; i++) {
        PerlClassEntry *e = &p->perl_classes.data[i];
        if (e->kind == kind && e->negated == negated) {
            *out = e->value;
            return true;
        }
    }
    NodeId translated = NODE_ID_BOT;
    if (p->global_ascii_perl) {
        NodeId pos = NODE_ID_BOT;
        switch (kind) {
            case RS_CLASS_PERL_KIND_WORD: {
                NodeId az  = regex_builder_mk_range_u8(tb, 'a', 'z');
                NodeId big = regex_builder_mk_range_u8(tb, 'A', 'Z');
                NodeId dig = regex_builder_mk_range_u8(tb, '0', '9');
                NodeId us  = regex_builder_mk_u8(tb, '_');
                NodeId xs[] = {az, big, dig, us};
                pos = regex_builder_mk_unions(tb, xs, 4);
                break;
            }
            case RS_CLASS_PERL_KIND_DIGIT:
                pos = regex_builder_mk_range_u8(tb, '0', '9');
                break;
            case RS_CLASS_PERL_KIND_SPACE: {
                NodeId sp  = regex_builder_mk_u8(tb, ' ');
                NodeId tab = regex_builder_mk_u8(tb, '\t');
                NodeId nl  = regex_builder_mk_u8(tb, '\n');
                NodeId cr  = regex_builder_mk_u8(tb, '\r');
                NodeId ff  = regex_builder_mk_u8(tb, 0x0C);
                NodeId vt  = regex_builder_mk_u8(tb, 0x0B);
                NodeId xs[] = {sp, tab, nl, cr, ff, vt};
                pos = regex_builder_mk_unions(tb, xs, 6);
                break;
            }
        }
        translated = negated ? neg_class(tb, pos) : pos;
    } else if (p->global_unicode) {
        switch (kind) {
            case RS_CLASS_PERL_KIND_WORD:
                if (p->global_full_unicode)
                    UnicodeClassCache_ensure_word_full(&p->unicode_classes, tb);
                else
                    UnicodeClassCache_ensure_word(&p->unicode_classes, tb);
                translated = negated
                    ? UnicodeClassCache_non_word(&p->unicode_classes)
                    : UnicodeClassCache_word(&p->unicode_classes);
                break;
            case RS_CLASS_PERL_KIND_DIGIT:
                if (p->global_full_unicode)
                    UnicodeClassCache_ensure_digit_full(&p->unicode_classes, tb);
                else
                    UnicodeClassCache_ensure_digit(&p->unicode_classes, tb);
                translated = negated
                    ? UnicodeClassCache_non_digit(&p->unicode_classes)
                    : UnicodeClassCache_digit(&p->unicode_classes);
                break;
            case RS_CLASS_PERL_KIND_SPACE:
                if (p->global_full_unicode)
                    UnicodeClassCache_ensure_space_full(&p->unicode_classes, tb);
                else
                    UnicodeClassCache_ensure_space(&p->unicode_classes, tb);
                translated = negated
                    ? UnicodeClassCache_non_space(&p->unicode_classes)
                    : UnicodeClassCache_space(&p->unicode_classes);
                break;
        }
    } else {
        NodeId pos = NODE_ID_BOT;
        switch (kind) {
            case RS_CLASS_PERL_KIND_WORD: {
                NodeId az  = regex_builder_mk_range_u8(tb, 'a', 'z');
                NodeId big = regex_builder_mk_range_u8(tb, 'A', 'Z');
                NodeId dig = regex_builder_mk_range_u8(tb, '0', '9');
                NodeId us  = regex_builder_mk_u8(tb, '_');
                NodeId xs[] = {az, big, dig, us};
                pos = regex_builder_mk_unions(tb, xs, 4);
                break;
            }
            case RS_CLASS_PERL_KIND_DIGIT:
                pos = regex_builder_mk_range_u8(tb, '0', '9');
                break;
            case RS_CLASS_PERL_KIND_SPACE: {
                NodeId sp  = regex_builder_mk_u8(tb, ' ');
                NodeId tab = regex_builder_mk_u8(tb, '\t');
                NodeId nl  = regex_builder_mk_u8(tb, '\n');
                NodeId cr  = regex_builder_mk_u8(tb, '\r');
                NodeId ff  = regex_builder_mk_u8(tb, 0x0C);
                NodeId vt  = regex_builder_mk_u8(tb, 0x0B);
                NodeId xs[] = {sp, tab, nl, cr, ff, vt};
                pos = regex_builder_mk_unions(tb, xs, 6);
                break;
            }
        }
        translated = negated ? regex_builder_mk_compl(tb, pos) : pos;
    }
    PerlClassEntry e = {.negated = negated, .kind = kind, .value = translated};
    n00b_list_push(p->perl_classes, e);
    *out = translated;
    return true;
}

// ---------------------------------------------------------------------------
// Forward decls for the larger conversion routines.
// ---------------------------------------------------------------------------

typedef enum {
    RS_CUI_NAMED,
    RS_CUI_NAMED_VALUE,
    RS_CUI_ONE_LETTER,
} rs_ClassUnicode_kind_tag;
extern rs_ClassUnicode_kind_tag
rs_ClassUnicode_kind_tag_of(const rs_ClassUnicode *c);

static WordCharKind parser_concat_neighbor_kind(const ast_Ast *const *asts,
                                                size_t n, size_t idx,
                                                ssize_t dir,
                                                n00b_allocator_t *allocator);

// word_char_kind — pure function (Rust associated function).
static WordCharKind parser_word_char_kind(const ast_Ast *ast, bool left,
                                          n00b_allocator_t *allocator)
{
    ast_Ast_tag t = ast_Ast_tag_of(ast);
    switch (t) {
        case AST_TAG_LITERAL: {
            const rs_Literal *lit = ast_Ast_as_literal(ast);
            uint32_t c = ast_Literal_char(lit);
            return is_word_byte((uint8_t)c) ? WCK_WORD : WCK_NON_WORD;
        }
        case AST_TAG_CLASS_PERL: {
            const rs_ClassPerl *cp = ast_Ast_as_class_perl(ast);
            rs_ClassPerlKind k     = ast_ClassPerl_kind(cp);
            bool             neg   = ast_ClassPerl_negated(cp);
            if (k == RS_CLASS_PERL_KIND_WORD)  return neg ? WCK_NON_WORD : WCK_WORD;
            if (k == RS_CLASS_PERL_KIND_SPACE) return neg ? WCK_UNKNOWN  : WCK_NON_WORD;
            if (k == RS_CLASS_PERL_KIND_DIGIT) return neg ? WCK_UNKNOWN  : WCK_WORD;
            return WCK_UNKNOWN;
        }
        case AST_TAG_DOT:
        case AST_TAG_TOP:
            return WCK_UNKNOWN;
        case AST_TAG_GROUP: {
            const ast_Group *g = ast_Ast_as_group(ast);
            return parser_word_char_kind(ast_Group_inner(g), left, allocator);
        }
        case AST_TAG_CONCAT: {
            const ast_Concat *c = ast_Ast_as_concat(ast);
            size_t n = ast_Concat_count(c);
            if (n == 0) return WCK_UNKNOWN;
            const ast_Ast **arr = n00b_alloc_array_with_opts(
                const ast_Ast *, n,
                &(n00b_alloc_opts_t){.allocator = allocator});
            for (size_t i = 0; i < n; i++) arr[i] = ast_Concat_get(c, i);
            size_t edge = left ? n - 1 : 0;
            WordCharKind kind = parser_word_char_kind(arr[edge], left, allocator);
            ssize_t dir = left ? -1 : 1;
            WordCharKind result;
            if (kind == WCK_MAYBE_WORD) {
                WordCharKind n2 = parser_concat_neighbor_kind(arr, n, edge, dir,
                                                              allocator);
                result = (n2 == WCK_WORD) ? WCK_WORD : WCK_MAYBE_WORD;
            } else if (kind == WCK_MAYBE_NON_WORD) {
                WordCharKind n2 = parser_concat_neighbor_kind(arr, n, edge, dir,
                                                              allocator);
                result = (n2 == WCK_NON_WORD) ? WCK_NON_WORD : WCK_MAYBE_NON_WORD;
            } else {
                result = kind;
            }
            n00b_free(arr);
            return result;
        }
        case AST_TAG_ALTERNATION: {
            const ast_Alternation *a = ast_Ast_as_alternation(ast);
            size_t n = ast_Alternation_count(a);
            if (n == 0) return WCK_UNKNOWN;
            WordCharKind first = parser_word_char_kind(ast_Alternation_get(a, 0),
                                                       left, allocator);
            for (size_t i = 1; i < n; i++) {
                if (parser_word_char_kind(ast_Alternation_get(a, i), left,
                                          allocator) != first) {
                    return WCK_UNKNOWN;
                }
            }
            return first;
        }
        case AST_TAG_REPETITION: {
            const ast_Repetition *r = ast_Ast_as_repetition(ast);
            WordCharKind inner = parser_word_char_kind(ast_Repetition_inner(r),
                                                       left, allocator);
            ast_RepetitionKind_tag rk = ast_Repetition_op_kind_tag(r);
            bool nullable = (rk == AST_REPETITION_ZERO_OR_ONE) ||
                            (rk == AST_REPETITION_ZERO_OR_MORE);
            if (rk == AST_REPETITION_RANGE) {
                ast_RepetitionRange_tag rr = ast_Repetition_op_range_tag(r);
                if (rr == AST_REPETITION_RANGE_BOUNDED) {
                    uint32_t lo, hi;
                    ast_Repetition_op_range_bounds(r, &lo, &hi);
                    if (lo == 0) nullable = true;
                    (void)hi;
                }
            }
            if (nullable) {
                if (inner == WCK_WORD)     return WCK_MAYBE_WORD;
                if (inner == WCK_NON_WORD) return WCK_MAYBE_NON_WORD;
                return WCK_UNKNOWN;
            }
            return inner;
        }
        case AST_TAG_LOOKAROUND: {
            const ast_Lookaround *la = ast_Ast_as_lookaround(ast);
            return parser_word_char_kind(ast_Lookaround_inner(la), left,
                                          allocator);
        }
        default:
            return WCK_UNKNOWN;
    }
}

static WordCharKind parser_concat_neighbor_kind(const ast_Ast *const *asts,
                                                size_t n, size_t idx,
                                                ssize_t dir,
                                                n00b_allocator_t *allocator)
{
    ssize_t next = (ssize_t)idx + dir;
    if (next < 0 || next >= (ssize_t)n) return WCK_EDGE;
    WordCharKind kind = parser_word_char_kind(asts[next], dir < 0, allocator);
    if (kind == WCK_MAYBE_WORD) {
        WordCharKind k2 = parser_concat_neighbor_kind(asts, n, (size_t)next, dir,
                                                       allocator);
        return (k2 == WCK_WORD) ? WCK_WORD : WCK_UNKNOWN;
    }
    if (kind == WCK_MAYBE_NON_WORD) {
        WordCharKind k2 = parser_concat_neighbor_kind(asts, n, (size_t)next, dir,
                                                       allocator);
        return (k2 == WCK_NON_WORD) ? WCK_NON_WORD : WCK_UNKNOWN;
    }
    return kind;
}

static const ast_Ast *parser_edge_class_ast(const ast_Ast *ast, bool left)
{
    ast_Ast_tag t = ast_Ast_tag_of(ast);
    switch (t) {
        case AST_TAG_LITERAL:
        case AST_TAG_CLASS_PERL:
        case AST_TAG_CLASS_BRACKETED:
        case AST_TAG_CLASS_UNICODE:
        case AST_TAG_DOT:
        case AST_TAG_TOP:
            return ast;
        case AST_TAG_GROUP:
            return parser_edge_class_ast(ast_Group_inner(ast_Ast_as_group(ast)), left);
        case AST_TAG_CONCAT: {
            const ast_Concat *c = ast_Ast_as_concat(ast);
            size_t n = ast_Concat_count(c);
            if (n == 0) return nullptr;
            return parser_edge_class_ast(ast_Concat_get(c, left ? n - 1 : 0), left);
        }
        case AST_TAG_REPETITION: {
            const ast_Repetition *r = ast_Ast_as_repetition(ast);
            ast_RepetitionKind_tag rk = ast_Repetition_op_kind_tag(r);
            bool nullable = (rk == AST_REPETITION_ZERO_OR_ONE) ||
                            (rk == AST_REPETITION_ZERO_OR_MORE);
            if (rk == AST_REPETITION_RANGE) {
                ast_RepetitionRange_tag rr = ast_Repetition_op_range_tag(r);
                if (rr == AST_REPETITION_RANGE_BOUNDED) {
                    uint32_t lo, hi;
                    ast_Repetition_op_range_bounds(r, &lo, &hi);
                    if (lo == 0) nullable = true;
                    (void)hi;
                }
            }
            if (nullable) return nullptr;
            return parser_edge_class_ast(ast_Repetition_inner(r), left);
        }
        default:
            return nullptr;
    }
}

// ---------------------------------------------------------------------------
// Forward decls for the AST → NodeId lowerings.
// ---------------------------------------------------------------------------

static bool parser_ast_to_node_id(ResharpParser *p, const ast_Ast *ast,
                                  rs_Translator *opt_tr,
                                  RegexBuilder *tb,
                                  NodeId *out, ParseError *err);

// resolve_word_kind
static bool parser_resolve_word_kind(ResharpParser *p,
                                     const ast_Ast *const *asts, size_t n,
                                     size_t idx, ssize_t dir,
                                     rs_Translator *opt_tr,
                                     RegexBuilder *tb,
                                     NodeId word_id,
                                     NodeId not_word_id,
                                     WordCharKind *out, ParseError *err)
{
    WordCharKind fast = parser_concat_neighbor_kind(asts, n, idx, dir,
                                                     p->allocator);
    if (fast != WCK_UNKNOWN) { *out = fast; return true; }
    size_t neighbor_idx = (size_t)((ssize_t)idx + dir);
    const ast_Ast *edge = parser_edge_class_ast(asts[neighbor_idx], dir < 0);
    NodeId node;
    if (edge) {
        if (!parser_ast_to_node_id(p, edge, opt_tr, tb, &node, err)) return false;
    } else {
        NodeId neighbor_node;
        if (!parser_ast_to_node_id(p, asts[neighbor_idx], opt_tr, tb,
                                   &neighbor_node, err)) return false;
        NodeId elim = regex_builder_try_elim_lookarounds(tb, neighbor_node);
        if (nodeid_eq(elim, NODE_ID_MISSING)) {
            *err = parser_error(p, parser_span(p),
                                AST_ERROR_KIND_UNSUPPORTED_RESHARP_REGEX);
            return false;
        }
        neighbor_node = elim;
        if (dir < 0) {
            n00b_result_t(NodeId) rev = regex_builder_reverse(tb, neighbor_node);
            if (!n00b_result_is_ok(rev)) {
                *err = parser_error(p, parser_span(p),
                                    AST_ERROR_KIND_UNSUPPORTED_RESHARP_REGEX);
                return false;
            }
            neighbor_node = n00b_result_get(rev);
        }
        NodeId word_prefix    = regex_builder_mk_concat(tb, word_id,     NODE_ID_TS);
        NodeId nonword_prefix = regex_builder_mk_concat(tb, not_word_id, NODE_ID_TS);
        bool known = false, sub = false;
        (void)regex_builder_subsumes_known(tb, word_prefix, neighbor_node, &known, &sub);
        if (known && sub) { *out = WCK_WORD; return true; }
        known = false; sub = false;
        (void)regex_builder_subsumes_known(tb, nonword_prefix, neighbor_node, &known, &sub);
        if (known && sub) { *out = WCK_NON_WORD; return true; }
        *out = WCK_UNKNOWN;
        return true;
    }
    bool known = false, sub = false;
    (void)regex_builder_subsumes_known(tb, word_id, node, &known, &sub);
    if (known && sub) { *out = WCK_WORD; return true; }
    known = false; sub = false;
    (void)regex_builder_subsumes_known(tb, not_word_id, node, &known, &sub);
    if (known && sub) { *out = WCK_NON_WORD; return true; }
    *out = WCK_UNKNOWN;
    return true;
}

static bool parser_merge_boundary_with_following_lookaheads(
    ResharpParser *p,
    const ast_Ast *const *asts, size_t n,
    size_t wb_idx, NodeId boundary_tail,
    rs_Translator *opt_tr, RegexBuilder *tb,
    NodeId *out_node, size_t *out_next, ParseError *err)
{
    size_t next = wb_idx + 1;
    VecNodeId la_bodies = n00b_list_new_private(NodeId, .scan_kind = N00B_GC_SCAN_KIND_NONE, .allocator = p->allocator);
    n00b_list_push(la_bodies, boundary_tail);
    while (next < n) {
        if (ast_Ast_tag_of(asts[next]) == AST_TAG_LOOKAROUND) {
            const ast_Lookaround *la = ast_Ast_as_lookaround(asts[next]);
            if (ast_Lookaround_kind(la) == AST_LOOKAROUND_POSITIVE_LOOKAHEAD) {
                NodeId body;
                if (!parser_ast_to_node_id(p, ast_Lookaround_inner(la),
                                           opt_tr, tb, &body, err)) {
                    n00b_list_free(la_bodies);
                    return false;
                }
                n00b_list_push(la_bodies,
                               regex_builder_mk_concat(tb, body, NODE_ID_TS));
                next += 1;
                continue;
            }
        }
        break;
    }
    NodeId merged = regex_builder_mk_inters(tb, la_bodies.data, la_bodies.len);
    n00b_list_free(la_bodies);
    *out_node = regex_builder_mk_lookahead(tb, merged, NODE_ID_MISSING, 0);
    *out_next = next;
    return true;
}

static bool parser_rewrite_word_boundary_in_concat(
    ResharpParser *p,
    const ast_Ast *const *asts, size_t n, size_t idx,
    rs_Translator *opt_tr, RegexBuilder *tb,
    NodeId *out_node, size_t *out_next, ParseError *err)
{
    NodeId word_id, not_word_id;
    if (p->global_full_unicode) {
        UnicodeClassCache_ensure_word_full(&p->unicode_classes, tb);
        word_id     = UnicodeClassCache_word(&p->unicode_classes);
        not_word_id = UnicodeClassCache_non_word(&p->unicode_classes);
    } else if (p->global_unicode && !p->global_ascii_perl) {
        UnicodeClassCache_ensure_word(&p->unicode_classes, tb);
        word_id     = UnicodeClassCache_word(&p->unicode_classes);
        not_word_id = UnicodeClassCache_non_word(&p->unicode_classes);
    } else {
        NodeId az  = regex_builder_mk_range_u8(tb, 'a', 'z');
        NodeId big = regex_builder_mk_range_u8(tb, 'A', 'Z');
        NodeId dig = regex_builder_mk_range_u8(tb, '0', '9');
        NodeId us  = regex_builder_mk_u8(tb, '_');
        NodeId xs[] = {az, big, dig, us};
        word_id     = regex_builder_mk_unions(tb, xs, 4);
        not_word_id = regex_builder_mk_compl(tb, word_id);
    }
    WordCharKind left, right;
    if (!parser_resolve_word_kind(p, asts, n, idx, -1, opt_tr, tb,
                                  word_id, not_word_id, &left, err)) return false;
    if (!parser_resolve_word_kind(p, asts, n, idx,  1, opt_tr, tb,
                                  word_id, not_word_id, &right, err)) return false;
    if ((left == WCK_NON_WORD && right == WCK_WORD) ||
        (left == WCK_WORD && right == WCK_NON_WORD)) {
        *out_node = NODE_ID_EPS;
        *out_next = idx + 1;
        return true;
    }
    if (left == WCK_WORD) {
        *out_node = regex_builder_mk_neg_lookahead(tb, word_id, 0);
        *out_next = idx + 1;
        return true;
    }
    if (left == WCK_NON_WORD) {
        NodeId tail = regex_builder_mk_concat(tb, word_id, NODE_ID_TS);
        return parser_merge_boundary_with_following_lookaheads(
            p, asts, n, idx, tail, opt_tr, tb, out_node, out_next, err);
    }
    if (right == WCK_WORD) {
        *out_node = regex_builder_mk_neg_lookbehind(tb, word_id);
        *out_next = idx + 1;
        return true;
    }
    if (right == WCK_NON_WORD) {
        *out_node = regex_builder_mk_lookbehind(tb, word_id, NODE_ID_MISSING);
        *out_next = idx + 1;
        return true;
    }
    *err = parser_error(p, parser_span(p), AST_ERROR_KIND_UNSUPPORTED_RESHARP_REGEX);
    return false;
}

// ---------------------------------------------------------------------------
// is_universal_perl_pair
// ---------------------------------------------------------------------------

static bool is_universal_perl_pair(const rs_ClassSetItem *item)
{
    if (!rs_ClassSetItem_is_union(item)) return false;
    if (rs_ClassSetItem_union_len(item) != 2) return false;
    const rs_ClassSetItem *i0 = rs_ClassSetItem_union_at(item, 0);
    const rs_ClassSetItem *i1 = rs_ClassSetItem_union_at(item, 1);
    if (!rs_ClassSetItem_is_perl(i0) || !rs_ClassSetItem_is_perl(i1)) return false;
    rs_ClassPerl a = rs_ClassSetItem_as_perl(i0);
    rs_ClassPerl b = rs_ClassSetItem_as_perl(i1);
    return ast_ClassPerl_kind(&a) == ast_ClassPerl_kind(&b)
        && ast_ClassPerl_negated(&a) != ast_ClassPerl_negated(&b);
}

// ---------------------------------------------------------------------------
// ast_to_node_id — translate parser AST → algebra NodeId.
// ---------------------------------------------------------------------------

static bool parser_ast_to_node_id(ResharpParser *p, const ast_Ast *ast,
                                  rs_Translator *opt_tr,
                                  RegexBuilder *tb,
                                  NodeId *out, ParseError *err)
{
    ast_Ast_tag t = ast_Ast_tag_of(ast);
    switch (t) {
        case AST_TAG_EMPTY:
            *out = NODE_ID_EPS;
            return true;

        case AST_TAG_FLAGS: {
            const ast_SetFlags *f = ast_Ast_as_flags(ast);
            if (ast_SetFlags_flag_state(f, AST_FLAG_SWAP_GREED) >= 0) {
                *err = parser_error(p, ast_SetFlags_span(f),
                                    AST_ERROR_KIND_UNSUPPORTED_RESHARP_REGEX);
                return false;
            }
            rs_TranslatorBuilder trb =
                resharp_parser_default_translator_builder(p);
            int v;
            if ((v = ast_SetFlags_flag_state(f, AST_FLAG_CASE_INSENSITIVE)) >= 0)
                rs_TranslatorBuilder_case_insensitive(&trb, v != 0);
            if ((v = ast_SetFlags_flag_state(f, AST_FLAG_UNICODE)) >= 0)
                rs_TranslatorBuilder_unicode(&trb, v != 0);
            if ((v = ast_SetFlags_flag_state(f, AST_FLAG_DOT_MATCHES_NEW_LINE)) >= 0)
                p->dot_all = (v != 0);
            if ((v = ast_SetFlags_flag_state(f, AST_FLAG_MULTI_LINE)) >= 0)
                p->multiline = (v != 0);
            if (opt_tr) {
                rs_Translator_free(opt_tr);
                *opt_tr = rs_TranslatorBuilder_build(&trb);
            } else {
                rs_Translator built = rs_TranslatorBuilder_build(&trb);
                rs_Translator_free(&built);
            }
            *out = NODE_ID_EPS;
            return true;
        }

        case AST_TAG_LITERAL: {
            const rs_Literal *l = ast_Ast_as_literal(ast);
            rs_Literal cloned = rs_Literal_clone(l);
            rs_Ast *ast_lit = rs_Ast_literal_owned(cloned);
            bool ok = parser_translator_to_node_id(p, ast_lit, opt_tr, tb, out, err);
            rs_Ast_free(ast_lit);
            return ok;
        }

        case AST_TAG_TOP:
            *out = NODE_ID_TOP;
            return true;

        case AST_TAG_DOT: {
            bool codepoint_dot = p->global_ascii_perl || p->global_full_unicode;
            rs_Hir *hirv;
            if (codepoint_dot && p->dot_all) {
                hirv = rs_Hir_dot_any_char();
            } else if (codepoint_dot && !p->dot_all) {
                hirv = rs_Hir_dot_any_char_except_lf();
            } else if (!codepoint_dot && p->dot_all) {
                *out = NODE_ID_TOP;
                return true;
            } else {
                hirv = rs_Hir_dot_any_byte_except_lf();
            }
            bool ok = parser_hir_to_node_id(p, hirv, tb, out, err);
            rs_Hir_free(hirv);
            return ok;
        }

        case AST_TAG_ASSERTION: {
            const ast_Assertion *a = ast_Ast_as_assertion(ast);
            ast_AssertionKind ak = ast_Assertion_kind(a);
            switch (ak) {
                case AST_ASSERTION_START_TEXT: *out = NODE_ID_BEGIN; return true;
                case AST_ASSERTION_END_TEXT:   *out = NODE_ID_END;   return true;
                case AST_ASSERTION_WORD_BOUNDARY:
                case AST_ASSERTION_NOT_WORD_BOUNDARY:
                    *err = parser_error(p, parser_span(p),
                                        AST_ERROR_KIND_UNSUPPORTED_RESHARP_REGEX);
                    return false;
                case AST_ASSERTION_START_LINE: {
                    if (!p->multiline) { *out = NODE_ID_BEGIN; return true; }
                    NodeId left  = NODE_ID_BEGIN;
                    NodeId right = regex_builder_mk_u8(tb, '\n');
                    NodeId u     = regex_builder_mk_union(tb, left, right);
                    *out = regex_builder_mk_lookbehind(tb, u, NODE_ID_MISSING);
                    return true;
                }
                case AST_ASSERTION_END_LINE: {
                    if (!p->multiline) { *out = NODE_ID_END; return true; }
                    NodeId left  = NODE_ID_END;
                    NodeId right = regex_builder_mk_u8(tb, '\n');
                    NodeId u     = regex_builder_mk_union(tb, left, right);
                    *out = regex_builder_mk_lookahead(tb, u, NODE_ID_MISSING, 0);
                    return true;
                }
                default:
                    *err = parser_error(p, ast_Assertion_span_get(a),
                                        AST_ERROR_KIND_UNSUPPORTED_RESHARP_REGEX);
                    return false;
            }
        }

        case AST_TAG_CLASS_UNICODE: {
            const rs_ClassUnicode *c = ast_Ast_as_class_unicode(ast);
            rs_ClassUnicode tmp = rs_ClassUnicode_clone(c);
            if (!ast_ClassUnicode_negated(c)) {
                if (rs_ClassUnicode_kind_tag_of(c) == RS_CUI_NAMED) {
                    size_t nlen;
                    const char *s = rs_ClassUnicode_named(c, &nlen);
                    if (nlen == 5 && memcmp(s, "ascii", 5) == 0) {
                        *out = regex_builder_mk_range_u8(tb, 0, 127);
                        return true;
                    }
                    if (nlen == 4 && memcmp(s, "utf8", 4) == 0) {
                        NodeId ascii = regex_builder_mk_range_u8(tb, 0, 127);
                        NodeId beta  = regex_builder_mk_range_u8(tb, 128, 0xBF);
                        NodeId c0    = regex_builder_mk_range_u8(tb, 0xC0, 0xDF);
                        NodeId c0p[] = {c0, beta};
                        NodeId c0s   = regex_builder_mk_concats(tb, c0p, 2);
                        NodeId e0    = regex_builder_mk_range_u8(tb, 0xE0, 0xEF);
                        NodeId e0p[] = {e0, beta, beta};
                        NodeId e0s   = regex_builder_mk_concats(tb, e0p, 3);
                        NodeId f0    = regex_builder_mk_range_u8(tb, 0xF0, 0xF7);
                        NodeId f0p[] = {f0, beta, beta, beta};
                        NodeId f0s   = regex_builder_mk_concats(tb, f0p, 4);
                        NodeId xs[]  = {ascii, c0s, e0s, f0s};
                        NodeId merged = regex_builder_mk_unions(tb, xs, 4);
                        *out = regex_builder_mk_star(tb, merged);
                        return true;
                    }
                    if (nlen == 3 && memcmp(s, "hex", 3) == 0) {
                        NodeId nums  = regex_builder_mk_range_u8(tb, '0', '9');
                        NodeId lets  = regex_builder_mk_range_u8(tb, 'a', 'f');
                        NodeId lets2 = regex_builder_mk_range_u8(tb, 'A', 'F');
                        NodeId xs[]  = {nums, lets, lets2};
                        *out = regex_builder_mk_unions(tb, xs, 3);
                        return true;
                    }
                }
            }
            rs_Ast *orig = rs_Ast_class_unicode_owned(tmp);
            bool ok = parser_translator_to_node_id(p, orig, opt_tr, tb, out, err);
            rs_Ast_free(orig);
            return ok;
        }

        case AST_TAG_CLASS_PERL: {
            const rs_ClassPerl *c = ast_Ast_as_class_perl(ast);
            return parser_get_class(p, ast_ClassPerl_negated(c),
                                    ast_ClassPerl_kind(c), tb, out, err);
        }

        case AST_TAG_CLASS_BRACKETED: {
            const rs_ClassBracketed *c = ast_Ast_as_class_bracketed(ast);
            rs_ClassSet kind = rs_ClassBracketed_kind_get(c);
            if (rs_ClassSet_is_item(&kind)) {
                rs_ClassSetItem item = rs_ClassSet_get_item(&kind);
                if (!rs_ClassBracketed_negated(c) && is_universal_perl_pair(&item)) {
                    *out = NODE_ID_TOP;
                    return true;
                }
                rs_ClassBracketed tmp = rs_ClassBracketed_clone(c);
                rs_Ast *orig = rs_Ast_class_bracketed_owned(tmp);
                bool ok = parser_translator_to_node_id(p, orig, opt_tr, tb, out, err);
                rs_Ast_free(orig);
                return ok;
            }
            *err = parser_error(p, rs_ClassBracketed_span(c),
                                AST_ERROR_KIND_UNSUPPORTED_RESHARP_REGEX);
            return false;
        }

        case AST_TAG_REPETITION: {
            const ast_Repetition *r = ast_Ast_as_repetition(ast);
            NodeId body;
            if (!parser_ast_to_node_id(p, ast_Repetition_inner(r),
                                       opt_tr, tb, &body, err)) return false;
            ast_RepetitionKind_tag rk = ast_Repetition_op_kind_tag(r);
            if (rk == AST_REPETITION_ZERO_OR_ONE) {
                *out = regex_builder_mk_opt(tb, body); return true;
            }
            if (rk == AST_REPETITION_ZERO_OR_MORE) {
                *out = regex_builder_mk_star(tb, body); return true;
            }
            if (rk == AST_REPETITION_ONE_OR_MORE) {
                *out = regex_builder_mk_plus(tb, body); return true;
            }
            ast_RepetitionRange_tag rr = ast_Repetition_op_range_tag(r);
            uint32_t lo, hi;
            ast_Repetition_op_range_bounds(r, &lo, &hi);
            if (rr == AST_REPETITION_RANGE_EXACTLY) {
                *out = regex_builder_mk_repeat(tb, body, lo, lo);
                return true;
            }
            if (rr == AST_REPETITION_RANGE_AT_LEAST) {
                NodeId rep = regex_builder_mk_repeat(tb, body, lo, lo);
                NodeId st  = regex_builder_mk_star(tb, body);
                *out = regex_builder_mk_concat(tb, rep, st);
                return true;
            }
            *out = regex_builder_mk_repeat(tb, body, lo, hi);
            return true;
        }

        case AST_TAG_LOOKAROUND: {
            const ast_Lookaround *g = ast_Ast_as_lookaround(ast);
            NodeId body;
            if (!parser_ast_to_node_id(p, ast_Lookaround_inner(g),
                                       opt_tr, tb, &body, err)) return false;
            ast_LookaroundKind lk = ast_Lookaround_kind(g);
            if ((lk == AST_LOOKAROUND_POSITIVE_LOOKAHEAD ||
                 lk == AST_LOOKAROUND_NEGATIVE_LOOKAHEAD) &&
                regex_builder_contains_lookbehind(body, tb)) {
                *err = parser_error(p, ast_Lookaround_span(g),
                                    AST_ERROR_KIND_UNSUPPORTED_RESHARP_REGEX);
                return false;
            }
            switch (lk) {
                case AST_LOOKAROUND_POSITIVE_LOOKAHEAD:
                    *out = regex_builder_mk_lookahead(tb, body, NODE_ID_MISSING, 0);
                    return true;
                case AST_LOOKAROUND_POSITIVE_LOOKBEHIND:
                    *out = regex_builder_mk_lookbehind(tb, body, NODE_ID_MISSING);
                    return true;
                case AST_LOOKAROUND_NEGATIVE_LOOKAHEAD:
                    *out = regex_builder_mk_neg_lookahead(tb, body, 0);
                    return true;
                case AST_LOOKAROUND_NEGATIVE_LOOKBEHIND:
                    *out = regex_builder_mk_neg_lookbehind(tb, body);
                    return true;
            }
            return false;
        }

        case AST_TAG_GROUP: {
            const ast_Group *g = ast_Ast_as_group(ast);
            if (ast_Group_kind_is_non_capturing(g)) {
                const ast_Flags *fl = ast_Group_kind_non_capturing_flags(g);
                if (!ast_Flags_items_empty(fl)) {
                    rs_TranslatorBuilder trb =
                        resharp_parser_default_translator_builder(p);
                    int v;
                    if ((v = ast_Flags_flag_state(fl, AST_FLAG_CASE_INSENSITIVE)) >= 0)
                        rs_TranslatorBuilder_case_insensitive(&trb, v != 0);
                    if ((v = ast_Flags_flag_state(fl, AST_FLAG_UNICODE)) >= 0)
                        rs_TranslatorBuilder_unicode(&trb, v != 0);
                    bool saved_dot_all = p->dot_all;
                    if ((v = ast_Flags_flag_state(fl, AST_FLAG_DOT_MATCHES_NEW_LINE)) >= 0)
                        p->dot_all = (v != 0);
                    bool saved_multiline = p->multiline;
                    if ((v = ast_Flags_flag_state(fl, AST_FLAG_MULTI_LINE)) >= 0)
                        p->multiline = (v != 0);
                    rs_Translator scoped = rs_TranslatorBuilder_build(&trb);
                    bool ok = parser_ast_to_node_id(p, ast_Group_inner(g),
                                                    &scoped, tb, out, err);
                    rs_Translator_free(&scoped);
                    p->dot_all   = saved_dot_all;
                    p->multiline = saved_multiline;
                    return ok;
                }
            }
            return parser_ast_to_node_id(p, ast_Group_inner(g), opt_tr, tb, out, err);
        }

        case AST_TAG_ALTERNATION: {
            const ast_Alternation *a = ast_Ast_as_alternation(ast);
            size_t n = ast_Alternation_count(a);
            VecNodeId children = n00b_list_new_private(NodeId, .scan_kind = N00B_GC_SCAN_KIND_NONE, .allocator = p->allocator);
            for (size_t i = 0; i < n; i++) {
                NodeId nid;
                if (!parser_ast_to_node_id(p, ast_Alternation_get(a, i),
                                           opt_tr, tb, &nid, err)) {
                    n00b_list_free(children);
                    return false;
                }
                n00b_list_push(children, nid);
            }
            *out = regex_builder_mk_unions(tb, children.data, children.len);
            n00b_list_free(children);
            return true;
        }

        case AST_TAG_CONCAT: {
            const ast_Concat *c = ast_Ast_as_concat(ast);
            size_t n = ast_Concat_count(c);
            const ast_Ast **arr = n == 0
                ? nullptr
                : n00b_alloc_array_with_opts(const ast_Ast *, n,
                      &(n00b_alloc_opts_t){.allocator = p->allocator});
            for (size_t k = 0; k < n; k++) arr[k] = ast_Concat_get(c, k);
            rs_Translator concat_translator      = {};
            bool          have_concat_translator = false;
            VecNodeId children = n00b_list_new_private(NodeId, .scan_kind = N00B_GC_SCAN_KIND_NONE, .allocator = p->allocator);
            size_t i  = 0;
            bool   ok = true;
            while (i < n) {
                const ast_Ast *child = arr[i];
                ast_Ast_tag tt = ast_Ast_tag_of(child);
                if (tt == AST_TAG_FLAGS) {
                    const ast_SetFlags *fl = ast_Ast_as_flags(child);
                    if (ast_SetFlags_flag_state(fl, AST_FLAG_SWAP_GREED) >= 0) {
                        *err = parser_error(p, ast_SetFlags_span(fl),
                                            AST_ERROR_KIND_UNSUPPORTED_RESHARP_REGEX);
                        ok = false; break;
                    }
                    rs_TranslatorBuilder trb =
                        resharp_parser_default_translator_builder(p);
                    int v;
                    if ((v = ast_SetFlags_flag_state(fl, AST_FLAG_CASE_INSENSITIVE)) >= 0)
                        rs_TranslatorBuilder_case_insensitive(&trb, v != 0);
                    if ((v = ast_SetFlags_flag_state(fl, AST_FLAG_UNICODE)) >= 0)
                        rs_TranslatorBuilder_unicode(&trb, v != 0);
                    if ((v = ast_SetFlags_flag_state(fl, AST_FLAG_DOT_MATCHES_NEW_LINE)) >= 0)
                        p->dot_all = (v != 0);
                    if ((v = ast_SetFlags_flag_state(fl, AST_FLAG_MULTI_LINE)) >= 0)
                        p->multiline = (v != 0);
                    if (have_concat_translator) rs_Translator_free(&concat_translator);
                    concat_translator = rs_TranslatorBuilder_build(&trb);
                    have_concat_translator = true;
                    if (opt_tr) {
                        rs_Translator_free(opt_tr);
                        rs_TranslatorBuilder trb2 =
                            resharp_parser_default_translator_builder(p);
                        if ((v = ast_SetFlags_flag_state(fl, AST_FLAG_CASE_INSENSITIVE)) >= 0)
                            rs_TranslatorBuilder_case_insensitive(&trb2, v != 0);
                        if ((v = ast_SetFlags_flag_state(fl, AST_FLAG_UNICODE)) >= 0)
                            rs_TranslatorBuilder_unicode(&trb2, v != 0);
                        *opt_tr = rs_TranslatorBuilder_build(&trb2);
                    }
                    i += 1;
                    continue;
                }
                if (tt == AST_TAG_ASSERTION) {
                    const ast_Assertion *a = ast_Ast_as_assertion(child);
                    if (ast_Assertion_kind(a) == AST_ASSERTION_WORD_BOUNDARY) {
                        NodeId nid;
                        size_t next_i;
                        if (!parser_rewrite_word_boundary_in_concat(
                                p, arr, n, i, opt_tr, tb, &nid, &next_i, err)) {
                            ok = false; break;
                        }
                        n00b_list_push(children, nid);
                        i = next_i;
                        continue;
                    }
                }
                NodeId nid;
                bool   sub_ok;
                if (have_concat_translator) {
                    sub_ok = parser_ast_to_node_id(p, child, &concat_translator,
                                                   tb, &nid, err);
                } else {
                    sub_ok = parser_ast_to_node_id(p, child, opt_tr, tb, &nid, err);
                }
                if (!sub_ok) { ok = false; break; }
                n00b_list_push(children, nid);
                i += 1;
            }
            if (arr) n00b_free(arr);
            if (have_concat_translator) rs_Translator_free(&concat_translator);
            if (!ok) { n00b_list_free(children); return false; }
            *out = regex_builder_mk_concats(tb, children.data, children.len);
            n00b_list_free(children);
            return true;
        }

        case AST_TAG_INTERSECTION: {
            const ast_Intersection *inter = ast_Ast_as_intersection(ast);
            size_t n = ast_Intersection_count(inter);
            VecNodeId children = n00b_list_new_private(NodeId, .scan_kind = N00B_GC_SCAN_KIND_NONE, .allocator = p->allocator);
            for (size_t i = 0; i < n; i++) {
                NodeId nid;
                if (!parser_ast_to_node_id(p, ast_Intersection_get(inter, i),
                                           opt_tr, tb, &nid, err)) {
                    n00b_list_free(children);
                    return false;
                }
                n00b_list_push(children, nid);
            }
            *out = regex_builder_mk_inters(tb, children.data, children.len);
            n00b_list_free(children);
            return true;
        }

        case AST_TAG_COMPLEMENT: {
            const ast_Complement *comp = ast_Ast_as_complement(ast);
            NodeId body;
            if (!parser_ast_to_node_id(p, ast_Complement_inner(comp),
                                       opt_tr, tb, &body, err)) return false;
            *out = regex_builder_mk_compl(tb, body);
            return true;
        }
    }
    *err = parser_error(p, parser_span(p), AST_ERROR_KIND_UNSUPPORTED_RESHARP_REGEX);
    return false;
}

// ---------------------------------------------------------------------------
// Forward decls for parse_inner.
// ---------------------------------------------------------------------------

static bool parser_parse_set_class(ResharpParser *p, rs_ClassBracketed *out,
                                   ParseError *err);
static bool parser_parse_uncounted_repetition(ResharpParser *p, ast_Concat concat,
                                              ast_RepetitionKind_tag kind,
                                              ast_Concat *out, ParseError *err);
static bool parser_parse_counted_repetition(ResharpParser *p, ast_Concat concat,
                                            ast_Concat *out, ParseError *err);
static bool parser_parse_primitive(ResharpParser *p, Primitive *out,
                                   ParseError *err);

static bool parser_parse_inner(ResharpParser *p, ast_Ast **out, ParseError *err)
{
    ast_Concat concat = ast_Concat_new(parser_span(p));
    while (true) {
        parser_bump_space(p);
        if (parser_is_eof(p)) break;
        uint32_t c = parser_char(p);
        ast_Concat next_concat;
        switch (c) {
            case '(':
                if (!parser_push_group(p, concat, &next_concat, err)) return false;
                concat = next_concat; break;
            case ')':
                if (!parser_pop_group(p, concat, &next_concat, err)) return false;
                concat = next_concat; break;
            case '|':
                if (!parser_push_alternate(p, concat, &next_concat, err)) return false;
                concat = next_concat; break;
            case '&':
                if (!parser_push_intersect(p, concat, &next_concat, err)) return false;
                concat = next_concat; break;
            case '~':
                if (!parser_push_compl_group(p, concat, &next_concat, err)) return false;
                concat = next_concat; break;
            case '[': {
                rs_ClassBracketed cls;
                if (!parser_parse_set_class(p, &cls, err)) {
                    parser_drop_in_flight_concat(concat, p->allocator);
                    return false;
                }
                ast_Concat_push_ast(&concat, ast_Ast_class_bracketed_owned(cls, p->allocator), p->allocator);
                break;
            }
            case '?':
                if (!parser_parse_uncounted_repetition(p, concat,
                                                       AST_REPETITION_ZERO_OR_ONE,
                                                       &next_concat, err)) return false;
                concat = next_concat; break;
            case '*':
                if (!parser_parse_uncounted_repetition(p, concat,
                                                       AST_REPETITION_ZERO_OR_MORE,
                                                       &next_concat, err)) return false;
                concat = next_concat; break;
            case '+':
                if (!parser_parse_uncounted_repetition(p, concat,
                                                       AST_REPETITION_ONE_OR_MORE,
                                                       &next_concat, err)) return false;
                concat = next_concat; break;
            case '{':
                if (!parser_parse_counted_repetition(p, concat, &next_concat, err))
                    return false;
                concat = next_concat; break;
            default: {
                Primitive prim;
                if (!parser_parse_primitive(p, &prim, err)) {
                    parser_drop_in_flight_concat(concat, p->allocator);
                    return false;
                }
                ast_Concat_push_ast(&concat, Primitive_into_ast(prim, p->allocator), p->allocator);
                break;
            }
        }
    }
    ast_Ast *ast;
    if (!parser_pop_group_end(p, concat, &ast, err)) return false;
    if (expanded_ast_size(ast, p->expanded_ast_limit) >= p->expanded_ast_limit
        || max_concat_length(ast) >= p->max_list_len) {
        *err = parser_error(p, *ast_Ast_span(ast),
                            AST_ERROR_KIND_UNSUPPORTED_RESHARP_REGEX);
        ast_Ast_free(ast);
        return false;
    }
    *out = ast;
    return true;
}

static bool parser_parse(ResharpParser *p, RegexBuilder *tb,
                         NodeId *out, ParseError *err)
{
    ast_Ast *ast;
    if (!parser_parse_inner(p, &ast, err)) return false;
    rs_TranslatorBuilder trb = resharp_parser_default_translator_builder(p);
    rs_Translator top_tr = rs_TranslatorBuilder_build(&trb);
    bool ok = parser_ast_to_node_id(p, ast, &top_tr, tb, out, err);
    rs_Translator_free(&top_tr);
    ast_Ast_free(ast);
    return ok;
}

// ---------------------------------------------------------------------------
// parse_uncounted_repetition / parse_counted_repetition
// ---------------------------------------------------------------------------

static bool parser_parse_uncounted_repetition(ResharpParser *p, ast_Concat concat,
                                              ast_RepetitionKind_tag kind,
                                              ast_Concat *out, ParseError *err)
{
    rs_Position op_start = parser_pos(p);
    ast_Ast    *ast      = ast_Concat_pop_ast(&concat);
    if (!ast) {
        *err = parser_error(p, parser_span(p), AST_ERROR_KIND_REPETITION_MISSING);
        parser_drop_in_flight_concat(concat, p->allocator);
        return false;
    }
    ast_Ast_tag tt = ast_Ast_tag_of(ast);
    if (tt == AST_TAG_EMPTY || tt == AST_TAG_FLAGS) {
        *err = parser_error(p, parser_span(p), AST_ERROR_KIND_REPETITION_MISSING);
        ast_Ast_free(ast);
        parser_drop_in_flight_concat(concat, p->allocator);
        return false;
    }
    if (parser_bump(p) && parser_char(p) == '?') {
        *err = parser_error(p, rs_Span_new(op_start, parser_pos(p)),
                            AST_ERROR_KIND_UNSUPPORTED_LAZY_QUANTIFIER);
        ast_Ast_free(ast);
        parser_drop_in_flight_concat(concat, p->allocator);
        return false;
    }
    rs_Span span    = ast_Ast_span_with_end(ast, parser_pos(p));
    rs_Span op_span = rs_Span_new(op_start, parser_pos(p));
    ast_Repetition rep = ast_Repetition_make(
        span, op_span, kind, 0, 0, AST_REPETITION_RANGE_EXACTLY, ast);
    ast_Concat_push_ast(&concat, ast_Ast_repetition_owned(rep, p->allocator), p->allocator);
    *out = concat;
    return true;
}

// parse_decimal — used by parse_counted_repetition.
static bool parser_parse_decimal(ResharpParser *p, uint32_t *out, ParseError *err)
{
    n00b_buffer_t *scratch = p->scratch;
    parser_scratch_clear(scratch);
    while (!parser_is_eof(p) && char_is_whitespace(parser_char(p))) {
        parser_bump(p);
    }
    rs_Position start = parser_pos(p);
    while (!parser_is_eof(p) && char_is_ascii_digit(parser_char(p))) {
        parser_scratch_push_char(scratch, parser_char(p));
        parser_bump_and_bump_space(p);
    }
    rs_Span span = rs_Span_new(start, parser_pos(p));
    while (!parser_is_eof(p) && char_is_whitespace(parser_char(p))) {
        parser_bump_and_bump_space(p);
    }
    if (scratch->byte_len == 0) {
        *err = parser_error(p, span, AST_ERROR_KIND_DECIMAL_EMPTY);
        return false;
    }
    bool ok;
    unsigned long val = parser_strtoul_n(scratch->data, scratch->byte_len, 10, &ok);
    if (!ok || val > UINT32_MAX) {
        *err = parser_error(p, span, AST_ERROR_KIND_DECIMAL_INVALID);
        return false;
    }
    *out = (uint32_t)val;
    return true;
}

static bool parser_repetition_range_is_valid(ast_RepetitionRange_tag rr,
                                             uint32_t lo, uint32_t hi)
{
    if (rr == AST_REPETITION_RANGE_BOUNDED) return lo <= hi;
    return true;
}

static bool parser_parse_counted_repetition(ResharpParser *p, ast_Concat concat,
                                            ast_Concat *out, ParseError *err)
{
    n00b_require(parser_char(p) == '{',
                 "parser_parse_counted_repetition: expected '{'");
    rs_Position start = parser_pos(p);
    ast_Ast    *ast   = ast_Concat_pop_ast(&concat);
    if (!ast) {
        *err = parser_error(p, parser_span(p), AST_ERROR_KIND_REPETITION_MISSING);
        parser_drop_in_flight_concat(concat, p->allocator);
        return false;
    }
    ast_Ast_tag tt = ast_Ast_tag_of(ast);
    if (tt == AST_TAG_EMPTY || tt == AST_TAG_FLAGS) {
        *err = parser_error(p, parser_span(p), AST_ERROR_KIND_REPETITION_MISSING);
        ast_Ast_free(ast);
        parser_drop_in_flight_concat(concat, p->allocator);
        return false;
    }
    if (!parser_bump_and_bump_space(p)) {
        *err = parser_error(p, rs_Span_new(start, parser_pos(p)),
                            AST_ERROR_KIND_REPETITION_COUNT_UNCLOSED);
        ast_Ast_free(ast);
        parser_drop_in_flight_concat(concat, p->allocator);
        return false;
    }
    ParseError tmp_err;
    uint32_t   cs_val = 0;
    bool       cs_ok  = parser_parse_decimal(p, &cs_val, &tmp_err);
    cs_ok = specialize_err(cs_ok, &tmp_err,
                           AST_ERROR_KIND_DECIMAL_EMPTY,
                           AST_ERROR_KIND_REPETITION_COUNT_DECIMAL_EMPTY);
    if (parser_is_eof(p)) {
        if (!cs_ok) ParseError_free(&tmp_err);
        *err = parser_error(p, rs_Span_new(start, parser_pos(p)),
                            AST_ERROR_KIND_REPETITION_COUNT_UNCLOSED);
        ast_Ast_free(ast);
        parser_drop_in_flight_concat(concat, p->allocator);
        return false;
    }
    uint32_t lo = 0, hi = 0;
    ast_RepetitionRange_tag rr;
    if (parser_char(p) == ',') {
        if (!parser_bump_and_bump_space(p)) {
            if (!cs_ok) ParseError_free(&tmp_err);
            *err = parser_error(p, rs_Span_new(start, parser_pos(p)),
                                AST_ERROR_KIND_REPETITION_COUNT_UNCLOSED);
            ast_Ast_free(ast);
            parser_drop_in_flight_concat(concat, p->allocator);
            return false;
        }
        if (parser_char(p) != '}') {
            uint32_t cs_value;
            if (cs_ok) {
                cs_value = cs_val;
            } else if (tmp_err.kind.tag == AST_ERROR_KIND_REPETITION_COUNT_DECIMAL_EMPTY) {
                if (p->empty_min_range) {
                    cs_value = 0;
                    ParseError_free(&tmp_err);
                } else {
                    *err = tmp_err;
                    ast_Ast_free(ast);
                    parser_drop_in_flight_concat(concat, p->allocator);
                    return false;
                }
            } else {
                *err = tmp_err;
                ast_Ast_free(ast);
                parser_drop_in_flight_concat(concat, p->allocator);
                return false;
            }
            uint32_t   cs_end;
            ParseError tmp2;
            bool ok2 = parser_parse_decimal(p, &cs_end, &tmp2);
            ok2 = specialize_err(ok2, &tmp2,
                                 AST_ERROR_KIND_DECIMAL_EMPTY,
                                 AST_ERROR_KIND_REPETITION_COUNT_DECIMAL_EMPTY);
            if (!ok2) {
                *err = tmp2;
                ast_Ast_free(ast);
                parser_drop_in_flight_concat(concat, p->allocator);
                return false;
            }
            lo = cs_value; hi = cs_end;
            rr = AST_REPETITION_RANGE_BOUNDED;
        } else {
            if (!cs_ok) {
                *err = tmp_err;
                ast_Ast_free(ast);
                parser_drop_in_flight_concat(concat, p->allocator);
                return false;
            }
            lo = cs_val; hi = 0;
            rr = AST_REPETITION_RANGE_AT_LEAST;
        }
    } else {
        if (!cs_ok) {
            *err = tmp_err;
            ast_Ast_free(ast);
            parser_drop_in_flight_concat(concat, p->allocator);
            return false;
        }
        lo = cs_val; hi = 0;
        rr = AST_REPETITION_RANGE_EXACTLY;
    }
    if (parser_is_eof(p) || parser_char(p) != '}') {
        *err = parser_error(p, rs_Span_new(start, parser_pos(p)),
                            AST_ERROR_KIND_REPETITION_COUNT_UNCLOSED);
        ast_Ast_free(ast);
        parser_drop_in_flight_concat(concat, p->allocator);
        return false;
    }
    if (parser_bump_and_bump_space(p) && parser_char(p) == '?') {
        *err = parser_error(p, rs_Span_new(start, parser_pos(p)),
                            AST_ERROR_KIND_UNSUPPORTED_LAZY_QUANTIFIER);
        ast_Ast_free(ast);
        parser_drop_in_flight_concat(concat, p->allocator);
        return false;
    }
    rs_Span op_span = rs_Span_new(start, parser_pos(p));
    if (!parser_repetition_range_is_valid(rr, lo, hi)) {
        *err = parser_error(p, op_span, AST_ERROR_KIND_REPETITION_COUNT_INVALID);
        ast_Ast_free(ast);
        parser_drop_in_flight_concat(concat, p->allocator);
        return false;
    }
    bool over_limit = false;
    if (rr == AST_REPETITION_RANGE_EXACTLY)  over_limit = lo > REPETITION_COUNT_LIMIT;
    if (rr == AST_REPETITION_RANGE_AT_LEAST) over_limit = lo > REPETITION_COUNT_LIMIT;
    if (rr == AST_REPETITION_RANGE_BOUNDED)
        over_limit = (lo > REPETITION_COUNT_LIMIT) || (hi > REPETITION_COUNT_LIMIT);
    if (over_limit) {
        *err = parser_error(p, op_span, AST_ERROR_KIND_UNSUPPORTED_RESHARP_REGEX);
        ast_Ast_free(ast);
        parser_drop_in_flight_concat(concat, p->allocator);
        return false;
    }
    rs_Span span = ast_Ast_span_with_end(ast, parser_pos(p));
    ast_Repetition rep = ast_Repetition_make(
        span, op_span, AST_REPETITION_RANGE, lo, hi, rr, ast);
    ast_Concat_push_ast(&concat, ast_Ast_repetition_owned(rep, p->allocator), p->allocator);
    *out = concat;
    return true;
}

// ---------------------------------------------------------------------------
// push_intersect — needs to be defined after push_or_add_alternation but
// before push_compl_group.  We forward-declared above; full impl here.
// ---------------------------------------------------------------------------

static void parser_push_or_add_intersect(ResharpParser *p, ast_Concat concat)
{
    if (p->stack_group.len > 0) {
        GroupState *top = &p->stack_group.data[p->stack_group.len - 1];
        if (n00b_variant_is_type(*top, ast_Intersection)) {
            ast_Intersection _inter = n00b_variant_get(*top, ast_Intersection);
            ast_Intersection_push_ast(&_inter,
                                      concat_into_ast_owned(concat, p->allocator), p->allocator);
            *top = n00b_variant_set(GroupState, ast_Intersection, _inter);
            return;
        }
    }
    rs_Span span = rs_Span_new(ast_Concat_span_start(&concat), parser_pos(p));
    ast_Intersection inter = ast_Intersection_new(span);
    ast_Intersection_push_ast(&inter, concat_into_ast_owned(concat, p->allocator), p->allocator);
    GroupState gs = n00b_variant_set(GroupState, ast_Intersection, inter);
    n00b_list_push(p->stack_group, gs);
}

static bool parser_push_intersect(ResharpParser *p, ast_Concat concat,
                                  ast_Concat *out, ParseError *err)
{
    (void)err;
    n00b_require(parser_char(p) == '&',
                 "parser_push_intersect: expected '&'");
    ast_Concat_set_span_end(&concat, parser_pos(p));
    parser_push_or_add_intersect(p, concat);
    parser_bump(p);
    *out = ast_Concat_new(parser_span(p));
    return true;
}

// ---------------------------------------------------------------------------
// parse_group / parse_capture_name / parse_flags / parse_flag
// ---------------------------------------------------------------------------

static bool parser_parse_capture_name(ResharpParser *p, uint32_t capture_index,
                                      ast_CaptureName *out, ParseError *err);
static bool parser_parse_flags(ResharpParser *p, ast_Flags *out, ParseError *err);
static bool parser_parse_flag (ResharpParser *p, ast_Flag  *out, ParseError *err);

static bool parser_parse_group(ResharpParser *p, ParseGroupResult *out,
                               ParseError *err)
{
    n00b_require(parser_char(p) == '(',
                 "parser_parse_group: expected '('");
    rs_Span open_span = parser_span_char(p);
    parser_bump(p);
    parser_bump_space(p);
    bool ahead, pos_;
    if (parser_is_lookaround_prefix(p, &ahead, &pos_)) {
        ast_LookaroundKind kind;
        if (pos_ && ahead)        kind = AST_LOOKAROUND_POSITIVE_LOOKAHEAD;
        else if (pos_ && !ahead)  kind = AST_LOOKAROUND_POSITIVE_LOOKBEHIND;
        else if (!pos_ && ahead)  kind = AST_LOOKAROUND_NEGATIVE_LOOKAHEAD;
        else                      kind = AST_LOOKAROUND_NEGATIVE_LOOKBEHIND;
        out->tag   = EITHER_RIGHT;
        out->group = ast_Group_new_lookaround(open_span, kind, parser_span(p));
        return true;
    }
    rs_Span inner_span    = parser_span(p);
    bool    starts_with_p = true;
    bool    matched_named = parser_bump_if(p, "?P<");
    if (!matched_named) {
        starts_with_p = false;
        matched_named = parser_bump_if(p, "?<");
    }
    if (matched_named) {
        uint32_t cidx;
        if (!parser_next_capture_index(p, open_span, &cidx, err)) return false;
        ast_CaptureName name;
        if (!parser_parse_capture_name(p, cidx, &name, err)) return false;
        out->tag   = EITHER_RIGHT;
        out->group = ast_Group_new_capture_name(open_span, starts_with_p,
                                                name, parser_span(p));
        return true;
    }
    if (parser_bump_if(p, "?")) {
        if (parser_is_eof(p)) {
            *err = parser_error(p, open_span, AST_ERROR_KIND_GROUP_UNCLOSED);
            return false;
        }
        ast_Flags flags;
        if (!parser_parse_flags(p, &flags, err)) return false;
        uint32_t char_end = parser_char(p);
        parser_bump(p);
        if (char_end == ')') {
            if (ast_Flags_is_empty(&flags)) {
                *err = parser_error(p, inner_span, AST_ERROR_KIND_REPETITION_MISSING);
                return false;
            }
            rs_Span span = open_span;
            span.end     = parser_pos(p);
            out->tag       = EITHER_LEFT;
            out->set_flags = ast_SetFlags_make(span, flags);
            return true;
        }
        n00b_require(char_end == ':',
                     "parser_parse_group: expected ':' at flag terminator");
        out->tag   = EITHER_RIGHT;
        out->group = ast_Group_new_non_capturing(open_span, flags, parser_span(p));
        return true;
    }
    uint32_t cidx;
    if (!parser_next_capture_index(p, open_span, &cidx, err)) return false;
    out->tag   = EITHER_RIGHT;
    out->group = ast_Group_new_capture_index(open_span, cidx, parser_span(p));
    return true;
}

static bool parser_parse_capture_name(ResharpParser *p, uint32_t capture_index,
                                      ast_CaptureName *out, ParseError *err)
{
    if (parser_is_eof(p)) {
        *err = parser_error(p, parser_span(p),
                            AST_ERROR_KIND_GROUP_NAME_UNEXPECTED_EOF);
        return false;
    }
    rs_Position start = parser_pos(p);
    while (true) {
        uint32_t c = parser_char(p);
        if (c == '>') break;
        bool first = (parser_pos(p).offset == start.offset);
        if (!is_capture_char(c, first)) {
            *err = parser_error(p, parser_span_char(p),
                                AST_ERROR_KIND_GROUP_NAME_INVALID);
            return false;
        }
        if (!parser_bump(p)) break;
    }
    rs_Position end = parser_pos(p);
    if (parser_is_eof(p)) {
        *err = parser_error(p, parser_span(p),
                            AST_ERROR_KIND_GROUP_NAME_UNEXPECTED_EOF);
        return false;
    }
    n00b_require(parser_char(p) == '>',
                 "parser_parse_capture_name: expected '>'");
    parser_bump(p);
    size_t name_len = end.offset - start.offset;
    if (name_len == 0) {
        *err = parser_error(p, rs_Span_new(start, start),
                            AST_ERROR_KIND_GROUP_NAME_EMPTY);
        return false;
    }
    size_t name_bytes = parser_ckd_add_sz(name_len, 1);
    char  *name       = n00b_alloc_array(char, name_bytes);
    memcpy(name, p->pattern + start.offset, name_len);
    name[name_len] = '\0';
    ast_CaptureName cap = ast_CaptureName_make(rs_Span_new(start, end),
                                               name, capture_index);
    if (!parser_add_capture_name(p, &cap, err)) {
        // Duplicate-rejection path: free the heap-owned `name` we still own.
        n00b_free(name);
        return false;
    }
    *out = cap;
    return true;
}

static bool parser_parse_flags(ResharpParser *p, ast_Flags *out, ParseError *err)
{
    ast_Flags flags = ast_Flags_new(parser_span(p));
    rs_Span   last_was_negation = {};
    bool      have_last_neg     = false;
    while (parser_char(p) != ':' && parser_char(p) != ')') {
        if (parser_char(p) == '-') {
            last_was_negation = parser_span_char(p);
            have_last_neg     = true;
            ast_FlagsItem item = ast_FlagsItem_negation(parser_span_char(p));
            int idx = ast_Flags_add_item(&flags, item, p->allocator);
            if (idx >= 0) {
                ast_FlagsItem orig = ast_Flags_get_item(&flags, (size_t)idx);
                *err = parser_error_with_span(
                    p, parser_span_char(p),
                    AST_ERROR_KIND_FLAG_REPEATED_NEGATION,
                    ast_FlagsItem_span(&orig));
                return false;
            }
        } else {
            have_last_neg = false;
            ast_Flag fl;
            if (!parser_parse_flag(p, &fl, err)) return false;
            ast_FlagsItem item = ast_FlagsItem_flag(parser_span_char(p), fl);
            int idx = ast_Flags_add_item(&flags, item, p->allocator);
            if (idx >= 0) {
                ast_FlagsItem orig = ast_Flags_get_item(&flags, (size_t)idx);
                *err = parser_error_with_span(
                    p, parser_span_char(p),
                    AST_ERROR_KIND_FLAG_DUPLICATE,
                    ast_FlagsItem_span(&orig));
                return false;
            }
        }
        if (!parser_bump(p)) {
            *err = parser_error(p, parser_span(p),
                                AST_ERROR_KIND_FLAG_UNEXPECTED_EOF);
            return false;
        }
    }
    if (have_last_neg) {
        *err = parser_error(p, last_was_negation,
                            AST_ERROR_KIND_FLAG_DANGLING_NEGATION);
        return false;
    }
    ast_Flags_set_span_end(&flags, parser_pos(p));
    *out = flags;
    return true;
}

static bool parser_parse_flag(ResharpParser *p, ast_Flag *out, ParseError *err)
{
    uint32_t c = parser_char(p);
    switch (c) {
        case 'i': *out = AST_FLAG_CASE_INSENSITIVE;     return true;
        case 'm': *out = AST_FLAG_MULTI_LINE;           return true;
        case 's': *out = AST_FLAG_DOT_MATCHES_NEW_LINE; return true;
        case 'U': *out = AST_FLAG_SWAP_GREED;           return true;
        case 'u': *out = AST_FLAG_UNICODE;              return true;
        case 'R': *out = AST_FLAG_CRLF;                 return true;
        case 'x': *out = AST_FLAG_IGNORE_WHITESPACE;    return true;
        default:
            *err = parser_error(p, parser_span_char(p),
                                AST_ERROR_KIND_FLAG_UNRECOGNIZED);
            return false;
    }
}

// ---------------------------------------------------------------------------
// parse_primitive / parse_escape and friends
// ---------------------------------------------------------------------------

static bool parser_parse_escape(ResharpParser *p, Primitive *out, ParseError *err);
static bool parser_maybe_parse_special_word_boundary(ResharpParser *p,
                                                     rs_Position wb_start,
                                                     bool *have_kind,
                                                     ast_AssertionKind *out_kind,
                                                     ParseError *err);
static rs_Literal parser_parse_octal(ResharpParser *p);
static bool parser_parse_hex(ResharpParser *p, rs_Literal *out, ParseError *err);
static bool parser_parse_hex_digits(ResharpParser *p, rs_HexLiteralKind kind,
                                    rs_Literal *out, ParseError *err);
static bool parser_parse_hex_brace(ResharpParser *p, rs_HexLiteralKind kind,
                                   rs_Literal *out, ParseError *err);
static rs_ClassPerl parser_parse_perl_class(ResharpParser *p);
static bool parser_parse_unicode_class(ResharpParser *p, rs_ClassUnicode *out,
                                       ParseError *err);

static bool parser_parse_primitive(ResharpParser *p, Primitive *out,
                                   ParseError *err)
{
    uint32_t c = parser_char(p);
    if (c == '\\') return parser_parse_escape(p, out, err);
    if (c == '_') {
        out->tag     = PRIM_TOP;
        out->as.span = parser_span_char(p);
        parser_bump(p);
        return true;
    }
    if (c == '.') {
        out->tag     = PRIM_DOT;
        out->as.span = parser_span_char(p);
        parser_bump(p);
        return true;
    }
    if (c == '^') {
        out->tag                  = PRIM_ASSERTION;
        out->as.assertion.span    = parser_span_char(p);
        out->as.assertion.kind    = AST_ASSERTION_START_LINE;
        parser_bump(p);
        return true;
    }
    if (c == '$') {
        out->tag                  = PRIM_ASSERTION;
        out->as.assertion.span    = parser_span_char(p);
        out->as.assertion.kind    = AST_ASSERTION_END_LINE;
        parser_bump(p);
        return true;
    }
    out->tag    = PRIM_LITERAL;
    out->as.lit = rs_Literal_make(parser_span_char(p),
                                  RS_LITERAL_KIND_VERBATIM, c);
    parser_bump(p);
    (void)err;
    return true;
}

static bool parser_parse_escape(ResharpParser *p, Primitive *out, ParseError *err)
{
    n00b_require(parser_char(p) == '\\',
                 "parser_parse_escape: expected '\\'");
    rs_Position start = parser_pos(p);
    if (!parser_bump(p)) {
        *err = parser_error(p, rs_Span_new(start, parser_pos(p)),
                            AST_ERROR_KIND_ESCAPE_UNEXPECTED_EOF);
        return false;
    }
    uint32_t c = parser_char(p);
    if (c >= '0' && c <= '9') {
        if (!p->octal) {
            *err = parser_error(p, rs_Span_new(start, parser_span_char(p).end),
                                AST_ERROR_KIND_UNSUPPORTED_BACKREFERENCE);
            return false;
        }
        rs_Literal lit = parser_parse_octal(p);
        rs_Literal_set_span_start(&lit, start);
        out->tag    = PRIM_LITERAL;
        out->as.lit = lit;
        return true;
    }
    if (c == 'x' || c == 'u' || c == 'U') {
        rs_Literal lit;
        if (!parser_parse_hex(p, &lit, err)) return false;
        rs_Literal_set_span_start(&lit, start);
        out->tag    = PRIM_LITERAL;
        out->as.lit = lit;
        return true;
    }
    if (c == 'p' || c == 'P') {
        rs_ClassUnicode cls;
        if (!parser_parse_unicode_class(p, &cls, err)) return false;
        rs_ClassUnicode_set_span_start(&cls, start);
        out->tag        = PRIM_UNICODE;
        out->as.unicode = cls;
        return true;
    }
    if (c == 'd' || c == 's' || c == 'w' ||
        c == 'D' || c == 'S' || c == 'W') {
        rs_ClassPerl cls = parser_parse_perl_class(p);
        rs_ClassPerl_set_span_start(&cls, start);
        out->tag     = PRIM_PERL;
        out->as.perl = cls;
        return true;
    }
    parser_bump(p);
    rs_Span span = rs_Span_new(start, parser_pos(p));
    if (parser_is_meta_character(c)) {
        out->tag    = PRIM_LITERAL;
        out->as.lit = rs_Literal_make(span, RS_LITERAL_KIND_META, c);
        return true;
    }
    if (parser_is_escapeable_character(c)) {
        out->tag    = PRIM_LITERAL;
        out->as.lit = rs_Literal_make(span, RS_LITERAL_KIND_SUPERFLUOUS, c);
        return true;
    }
    switch (c) {
        case 'a': out->tag = PRIM_LITERAL;
                  out->as.lit = rs_Literal_make_special(span,
                      RS_SPECIAL_LITERAL_BELL, 0x07);
                  return true;
        case 'f': out->tag = PRIM_LITERAL;
                  out->as.lit = rs_Literal_make_special(span,
                      RS_SPECIAL_LITERAL_FORM_FEED, 0x0C);
                  return true;
        case 't': out->tag = PRIM_LITERAL;
                  out->as.lit = rs_Literal_make_special(span,
                      RS_SPECIAL_LITERAL_TAB, '\t');
                  return true;
        case 'n': out->tag = PRIM_LITERAL;
                  out->as.lit = rs_Literal_make_special(span,
                      RS_SPECIAL_LITERAL_LINE_FEED, '\n');
                  return true;
        case 'r': out->tag = PRIM_LITERAL;
                  out->as.lit = rs_Literal_make_special(span,
                      RS_SPECIAL_LITERAL_CARRIAGE_RETURN, '\r');
                  return true;
        case 'v': out->tag = PRIM_LITERAL;
                  out->as.lit = rs_Literal_make_special(span,
                      RS_SPECIAL_LITERAL_VERTICAL_TAB, 0x0B);
                  return true;
        case 'A': out->tag = PRIM_ASSERTION;
                  out->as.assertion.span = span;
                  out->as.assertion.kind = AST_ASSERTION_START_TEXT;
                  return true;
        case 'z': out->tag = PRIM_ASSERTION;
                  out->as.assertion.span = span;
                  out->as.assertion.kind = AST_ASSERTION_END_TEXT;
                  return true;
        case 'b': {
            ast_Assertion wb;
            wb.span = span;
            wb.kind = AST_ASSERTION_WORD_BOUNDARY;
            if (!parser_is_eof(p) && parser_char(p) == '{') {
                bool have_kind = false;
                ast_AssertionKind kind;
                if (!parser_maybe_parse_special_word_boundary(
                        p, start, &have_kind, &kind, err)) return false;
                if (have_kind) {
                    wb.kind     = kind;
                    wb.span.end = parser_pos(p);
                }
            }
            out->tag          = PRIM_ASSERTION;
            out->as.assertion = wb;
            return true;
        }
        case 'B':
            out->tag = PRIM_ASSERTION;
            out->as.assertion.span = span;
            out->as.assertion.kind = AST_ASSERTION_NOT_WORD_BOUNDARY;
            return true;
        case '<':
            out->tag = PRIM_ASSERTION;
            out->as.assertion.span = span;
            out->as.assertion.kind = AST_ASSERTION_WORD_BOUNDARY_START_ANGLE;
            return true;
        case '>':
            out->tag = PRIM_ASSERTION;
            out->as.assertion.span = span;
            out->as.assertion.kind = AST_ASSERTION_WORD_BOUNDARY_END_ANGLE;
            return true;
        default:
            *err = parser_error(p, span, AST_ERROR_KIND_ESCAPE_UNRECOGNIZED);
            return false;
    }
}

static bool parser_maybe_parse_special_word_boundary(ResharpParser *p,
                                                     rs_Position wb_start,
                                                     bool *have_kind,
                                                     ast_AssertionKind *out_kind,
                                                     ParseError *err)
{
    n00b_require(parser_char(p) == '{',
                 "parser_maybe_parse_special_word_boundary: expected '{'");
    *have_kind = false;
    rs_Position start = parser_pos(p);
    if (!parser_bump_and_bump_space(p)) {
        *err = parser_error(p, rs_Span_new(wb_start, parser_pos(p)),
                            AST_ERROR_KIND_SPECIAL_WORD_OR_REPETITION_UNEXPECTED_EOF);
        return false;
    }
    rs_Position start_contents = parser_pos(p);
    uint32_t cc = parser_char(p);
    bool ok = (cc >= 'A' && cc <= 'Z') || (cc >= 'a' && cc <= 'z') || cc == '-';
    if (!ok) {
        p->pos = start;
        return true;
    }

    n00b_buffer_t *scratch = p->scratch;
    parser_scratch_clear(scratch);
    while (!parser_is_eof(p)) {
        uint32_t c = parser_char(p);
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-')) break;
        parser_scratch_push_char(scratch, c);
        parser_bump_and_bump_space(p);
    }
    if (parser_is_eof(p) || parser_char(p) != '}') {
        *err = parser_error(p, rs_Span_new(start, parser_pos(p)),
                            AST_ERROR_KIND_SPECIAL_WORD_BOUNDARY_UNCLOSED);
        return false;
    }
    rs_Position end = parser_pos(p);
    parser_bump(p);
    if (scratch->byte_len == 5 && memcmp(scratch->data, "start", 5) == 0) {
        *out_kind = AST_ASSERTION_WORD_BOUNDARY_START;
    } else if (scratch->byte_len == 3 && memcmp(scratch->data, "end", 3) == 0) {
        *out_kind = AST_ASSERTION_WORD_BOUNDARY_END;
    } else if (scratch->byte_len == 10 && memcmp(scratch->data, "start-half", 10) == 0) {
        *out_kind = AST_ASSERTION_WORD_BOUNDARY_START_HALF;
    } else if (scratch->byte_len == 8 && memcmp(scratch->data, "end-half", 8) == 0) {
        *out_kind = AST_ASSERTION_WORD_BOUNDARY_END_HALF;
    } else {
        *err = parser_error(p, rs_Span_new(start_contents, end),
                            AST_ERROR_KIND_SPECIAL_WORD_BOUNDARY_UNRECOGNIZED);
        return false;
    }
    *have_kind = true;
    return true;
}

static rs_Literal parser_parse_octal(ResharpParser *p)
{
    n00b_require(p->octal, "parser_parse_octal: octal flag not set");
    n00b_require(parser_char(p) >= '0' && parser_char(p) <= '7',
                 "parser_parse_octal: expected octal digit '0'..'7'");
    rs_Position start = parser_pos(p);
    while (parser_bump(p)
           && parser_char(p) >= '0' && parser_char(p) <= '7'
           && (parser_pos(p).offset - start.offset) <= 2) {}
    rs_Position end = parser_pos(p);
    size_t n = end.offset - start.offset;
    if (n > 7) n = 7;
    bool ok;
    unsigned long val = parser_strtoul_n(p->pattern + start.offset, n, 8, &ok);
    (void)ok;
    return rs_Literal_make_octal(rs_Span_new(start, end), (uint32_t)val);
}

static bool parser_parse_hex(ResharpParser *p, rs_Literal *out, ParseError *err)
{
    n00b_require(parser_char(p) == 'x' || parser_char(p) == 'u'
                 || parser_char(p) == 'U',
                 "parser_parse_hex: expected 'x', 'u', or 'U'");
    rs_HexLiteralKind hex_kind;
    if      (parser_char(p) == 'x') hex_kind = RS_HEX_LITERAL_X;
    else if (parser_char(p) == 'u') hex_kind = RS_HEX_LITERAL_UNICODE_SHORT;
    else                            hex_kind = RS_HEX_LITERAL_UNICODE_LONG;
    if (!parser_bump_and_bump_space(p)) {
        *err = parser_error(p, parser_span(p),
                            AST_ERROR_KIND_ESCAPE_UNEXPECTED_EOF);
        return false;
    }
    if (parser_char(p) == '{') return parser_parse_hex_brace(p, hex_kind, out, err);
    return parser_parse_hex_digits(p, hex_kind, out, err);
}

static bool parser_parse_hex_digits(ResharpParser *p, rs_HexLiteralKind kind,
                                    rs_Literal *out, ParseError *err)
{
    n00b_buffer_t *scratch = p->scratch;
    parser_scratch_clear(scratch);
    rs_Position start = parser_pos(p);
    size_t digits = rs_HexLiteralKind_digits(kind);
    for (size_t i = 0; i < digits; i++) {
        if (i > 0 && !parser_bump_and_bump_space(p)) {
            *err = parser_error(p, parser_span(p),
                                AST_ERROR_KIND_ESCAPE_UNEXPECTED_EOF);
            return false;
        }
        if (!is_hex_char(parser_char(p))) {
            *err = parser_error(p, parser_span_char(p),
                                AST_ERROR_KIND_ESCAPE_HEX_INVALID_DIGIT);
            return false;
        }
        parser_scratch_push_char(scratch, parser_char(p));
    }
    parser_bump_and_bump_space(p);
    rs_Position end = parser_pos(p);
    bool ok;
    unsigned long val = parser_strtoul_n(scratch->data, scratch->byte_len, 16, &ok);
    if (!ok || val > 0x10FFFFu) {
        *err = parser_error(p, rs_Span_new(start, end),
                            AST_ERROR_KIND_ESCAPE_HEX_INVALID);
        return false;
    }
    *out = rs_Literal_make_hex_fixed(rs_Span_new(start, end), kind, (uint32_t)val);
    return true;
}

static bool parser_parse_hex_brace(ResharpParser *p, rs_HexLiteralKind kind,
                                   rs_Literal *out, ParseError *err)
{
    n00b_buffer_t *scratch = p->scratch;
    parser_scratch_clear(scratch);
    rs_Position brace_pos = parser_pos(p);
    rs_Position start     = parser_span_char(p).end;
    while (parser_bump_and_bump_space(p) && parser_char(p) != '}') {
        if (!is_hex_char(parser_char(p))) {
            *err = parser_error(p, parser_span_char(p),
                                AST_ERROR_KIND_ESCAPE_HEX_INVALID_DIGIT);
            return false;
        }
        parser_scratch_push_char(scratch, parser_char(p));
    }
    if (parser_is_eof(p)) {
        *err = parser_error(p, rs_Span_new(brace_pos, parser_pos(p)),
                            AST_ERROR_KIND_ESCAPE_UNEXPECTED_EOF);
        return false;
    }
    rs_Position end = parser_pos(p);
    n00b_require(parser_char(p) == '}',
                 "parser_parse_hex_brace: expected '}'");
    parser_bump_and_bump_space(p);
    if (scratch->byte_len == 0) {
        *err = parser_error(p, rs_Span_new(brace_pos, parser_pos(p)),
                            AST_ERROR_KIND_ESCAPE_HEX_EMPTY);
        return false;
    }
    bool ok;
    unsigned long val = parser_strtoul_n(scratch->data, scratch->byte_len, 16, &ok);
    if (!ok || val > 0x10FFFFu) {
        *err = parser_error(p, rs_Span_new(start, end),
                            AST_ERROR_KIND_ESCAPE_HEX_INVALID);
        return false;
    }
    *out = rs_Literal_make_hex_brace(rs_Span_new(start, parser_pos(p)),
                                     kind, (uint32_t)val);
    return true;
}

static rs_ClassPerl parser_parse_perl_class(ResharpParser *p)
{
    uint32_t c    = parser_char(p);
    rs_Span  span = parser_span_char(p);
    parser_bump(p);
    bool             negated;
    rs_ClassPerlKind kind;
    switch (c) {
        case 'd': negated = false; kind = RS_CLASS_PERL_KIND_DIGIT; break;
        case 'D': negated = true;  kind = RS_CLASS_PERL_KIND_DIGIT; break;
        case 's': negated = false; kind = RS_CLASS_PERL_KIND_SPACE; break;
        case 'S': negated = true;  kind = RS_CLASS_PERL_KIND_SPACE; break;
        case 'w': negated = false; kind = RS_CLASS_PERL_KIND_WORD;  break;
        case 'W': negated = true;  kind = RS_CLASS_PERL_KIND_WORD;  break;
        default:
            n00b_panic("parser_parse_perl_class: expected valid Perl class");
    }
    return rs_ClassPerl_make(span, kind, negated);
}

static char *strdup_n_owned(const char *s, size_t n)
{
    size_t bytes = parser_ckd_add_sz(n, 1);
    char  *d     = n00b_alloc_array(char, bytes);
    if (n > 0) memcpy(d, s, n);
    d[n] = '\0';
    return d;
}

static bool parser_parse_unicode_class(ResharpParser *p, rs_ClassUnicode *out,
                                       ParseError *err)
{
    n00b_require(parser_char(p) == 'p' || parser_char(p) == 'P',
                 "parser_parse_unicode_class: expected 'p' or 'P'");
    n00b_buffer_t *scratch = p->scratch;
    parser_scratch_clear(scratch);
    bool negated = (parser_char(p) == 'P');
    if (!parser_bump_and_bump_space(p)) {
        *err = parser_error(p, parser_span(p),
                            AST_ERROR_KIND_ESCAPE_UNEXPECTED_EOF);
        return false;
    }
    rs_Position start;
    if (parser_char(p) == '{') {
        start = parser_span_char(p).end;
        while (parser_bump_and_bump_space(p) && parser_char(p) != '}') {
            parser_scratch_push_char(scratch, parser_char(p));
        }
        if (parser_is_eof(p)) {
            *err = parser_error(p, parser_span(p),
                                AST_ERROR_KIND_ESCAPE_UNEXPECTED_EOF);
            return false;
        }
        n00b_require(parser_char(p) == '}',
                     "parser_parse_unicode_class: expected '}'");
        parser_bump(p);
        const char *name = scratch->data ? scratch->data : "";
        size_t      nlen = scratch->byte_len;
        const char *neq  = nullptr;
        for (size_t i = 0; i + 1 < nlen; i++) {
            if (name[i] == '!' && name[i + 1] == '=') { neq = name + i; break; }
        }
        if (neq) {
            size_t i  = (size_t)(neq - name);
            char  *nm = strdup_n_owned(name, i);
            char  *vl = strdup_n_owned(name + i + 2, nlen - i - 2);
            *out = rs_ClassUnicode_make_named_value(
                rs_Span_new(start, parser_pos(p)), negated,
                RS_CLASS_UNICODE_OP_NOT_EQUAL, nm, vl);
            return true;
        }
        const char *col = parser_memchr_byte(name, ':', nlen);
        if (col) {
            size_t i  = (size_t)(col - name);
            char  *nm = strdup_n_owned(name, i);
            char  *vl = strdup_n_owned(name + i + 1, nlen - i - 1);
            *out = rs_ClassUnicode_make_named_value(
                rs_Span_new(start, parser_pos(p)), negated,
                RS_CLASS_UNICODE_OP_COLON, nm, vl);
            return true;
        }
        const char *eq = parser_memchr_byte(name, '=', nlen);
        if (eq) {
            size_t i  = (size_t)(eq - name);
            char  *nm = strdup_n_owned(name, i);
            char  *vl = strdup_n_owned(name + i + 1, nlen - i - 1);
            *out = rs_ClassUnicode_make_named_value(
                rs_Span_new(start, parser_pos(p)), negated,
                RS_CLASS_UNICODE_OP_EQUAL, nm, vl);
            return true;
        }
        char *nm = strdup_n_owned(name, nlen);
        *out = rs_ClassUnicode_make_named(rs_Span_new(start, parser_pos(p)),
                                          negated, nm);
        return true;
    }
    start = parser_pos(p);
    uint32_t c = parser_char(p);
    if (c == '\\') {
        *err = parser_error(p, parser_span_char(p),
                            AST_ERROR_KIND_UNICODE_CLASS_INVALID);
        return false;
    }
    parser_bump_and_bump_space(p);
    *out = rs_ClassUnicode_make_one_letter(rs_Span_new(start, parser_pos(p)),
                                           negated, c);
    return true;
}

// ---------------------------------------------------------------------------
// parse_set_class / parse_set_class_range / parse_set_class_item /
// parse_set_class_open / maybe_parse_ascii_class
// ---------------------------------------------------------------------------

static bool parser_parse_set_class_range(ResharpParser *p, rs_ClassSetItem *out,
                                         ParseError *err);
static bool parser_parse_set_class_item(ResharpParser *p, Primitive *out,
                                        ParseError *err);
static bool parser_maybe_parse_ascii_class(ResharpParser *p, bool *have,
                                           rs_ClassAscii *out);

static bool parser_parse_set_class(ResharpParser *p, rs_ClassBracketed *out,
                                   ParseError *err)
{
    n00b_require(parser_char(p) == '[',
                 "parser_parse_set_class: expected '['");
    rs_ClassSetUnion union_ = rs_ClassSetUnion_new(parser_span(p));
    while (true) {
        parser_bump_space(p);
        if (parser_is_eof(p)) {
            *err = parser_unclosed_class_error(p);
            return false;
        }
        uint32_t c = parser_char(p);
        if (c == '[') {
            if (p->stack_class.len > 0) {
                bool          have_ascii = false;
                rs_ClassAscii cls;
                if (!parser_maybe_parse_ascii_class(p, &have_ascii, &cls)) {
                    // defensive — current implementation always returns true
                }
                if (have_ascii) {
                    rs_ClassSetUnion_push(&union_, rs_ClassSetItem_ascii(cls));
                    continue;
                }
            }
            rs_ClassSetUnion next;
            if (!parser_push_class_open(p, union_, &next, err)) return false;
            union_ = next;
            continue;
        }
        if (c == ']') {
            PopClassResult pr;
            if (!parser_pop_class(p, union_, &pr, err)) return false;
            if (pr.tag == EITHER_LEFT) {
                union_ = pr.left;
                continue;
            } else {
                *out = pr.right;
                return true;
            }
        }
        uint32_t pk;
        if (c == '&' && parser_peek(p, &pk) && pk == '&') {
            n00b_require(parser_bump_if(p, "&&"),
                         "parser_parse_set_class: pre-screened '&&' bump failed");
            union_ = parser_push_class_op(p, RS_CLASS_SET_BINARY_OP_INTERSECTION, union_);
            continue;
        }
        if (c == '-' && parser_peek(p, &pk) && pk == '-') {
            n00b_require(parser_bump_if(p, "--"),
                         "parser_parse_set_class: pre-screened '--' bump failed");
            union_ = parser_push_class_op(p, RS_CLASS_SET_BINARY_OP_DIFFERENCE, union_);
            continue;
        }
        if (c == '~' && parser_peek(p, &pk) && pk == '~') {
            n00b_require(parser_bump_if(p, "~~"),
                         "parser_parse_set_class: pre-screened '~~' bump failed");
            union_ = parser_push_class_op(p,
                                          RS_CLASS_SET_BINARY_OP_SYMMETRIC_DIFFERENCE,
                                          union_);
            continue;
        }
        rs_ClassSetItem item;
        if (!parser_parse_set_class_range(p, &item, err)) return false;
        rs_ClassSetUnion_push(&union_, item);
    }
}

static bool parser_parse_set_class_range(ResharpParser *p, rs_ClassSetItem *out,
                                         ParseError *err)
{
    Primitive prim1;
    if (!parser_parse_set_class_item(p, &prim1, err)) return false;
    parser_bump_space(p);
    if (parser_is_eof(p)) {
        *err = parser_unclosed_class_error(p);
        return false;
    }
    uint32_t pk;
    if (parser_char(p) != '-' ||
        (parser_peek_space(p, &pk) && pk == ']') ||
        (parser_peek_space(p, &pk) && pk == '-')) {
        return Primitive_into_class_set_item(prim1, p, out, err);
    }
    if (!parser_bump_and_bump_space(p)) {
        *err = parser_unclosed_class_error(p);
        return false;
    }
    Primitive prim2;
    if (!parser_parse_set_class_item(p, &prim2, err)) return false;
    rs_Literal start_lit, end_lit;
    if (!Primitive_into_class_literal(prim1, p, &start_lit, err)) return false;
    if (!Primitive_into_class_literal(prim2, p, &end_lit,   err)) return false;
    rs_Span rspan = rs_Span_new(Primitive_span(&prim1)->start,
                                Primitive_span(&prim2)->end);
    rs_ClassSetRange range = rs_ClassSetRange_make(rspan, start_lit, end_lit);
    if (!rs_ClassSetRange_is_valid(&range)) {
        *err = parser_error(p, rspan, AST_ERROR_KIND_CLASS_RANGE_INVALID);
        return false;
    }
    *out = rs_ClassSetItem_range(range);
    return true;
}

static bool parser_parse_set_class_item(ResharpParser *p, Primitive *out,
                                        ParseError *err)
{
    if (parser_char(p) == '\\') return parser_parse_escape(p, out, err);
    out->tag    = PRIM_LITERAL;
    out->as.lit = rs_Literal_make(parser_span_char(p),
                                  RS_LITERAL_KIND_VERBATIM, parser_char(p));
    parser_bump(p);
    return true;
}

static bool parser_parse_set_class_open(ResharpParser *p,
                                        rs_ClassBracketed *out_set,
                                        rs_ClassSetUnion *out_union,
                                        ParseError *err)
{
    n00b_require(parser_char(p) == '[',
                 "parser_parse_set_class_open: expected '['");
    rs_Position start = parser_pos(p);
    if (!parser_bump_and_bump_space(p)) {
        *err = parser_error(p, rs_Span_new(start, parser_pos(p)),
                            AST_ERROR_KIND_CLASS_UNCLOSED);
        return false;
    }
    bool negated;
    if (parser_char(p) != '^') {
        negated = false;
    } else {
        if (!parser_bump_and_bump_space(p)) {
            *err = parser_error(p, rs_Span_new(start, parser_pos(p)),
                                AST_ERROR_KIND_CLASS_UNCLOSED);
            return false;
        }
        negated = true;
    }
    rs_ClassSetUnion union_ = rs_ClassSetUnion_new(parser_span(p));
    while (parser_char(p) == '-') {
        rs_Literal dash = rs_Literal_make(parser_span_char(p),
                                          RS_LITERAL_KIND_VERBATIM, '-');
        rs_ClassSetItem item = rs_ClassSetItem_literal(dash);
        rs_ClassSetUnion_push(&union_, item);
        if (!parser_bump_and_bump_space(p)) {
            *err = parser_error(p, rs_Span_new(start, start),
                                AST_ERROR_KIND_CLASS_UNCLOSED);
            return false;
        }
    }
    if (rs_ClassSetUnion_is_empty(&union_) && parser_char(p) == ']') {
        rs_Literal br = rs_Literal_make(parser_span_char(p),
                                        RS_LITERAL_KIND_VERBATIM, ']');
        rs_ClassSetUnion_push(&union_, rs_ClassSetItem_literal(br));
        if (!parser_bump_and_bump_space(p)) {
            *err = parser_error(p, rs_Span_new(start, parser_pos(p)),
                                AST_ERROR_KIND_CLASS_UNCLOSED);
            return false;
        }
    }
    rs_Position u_start = rs_ClassSetUnion_span_start(&union_);
    rs_ClassSetUnion empty_inner = rs_ClassSetUnion_new(rs_Span_new(u_start, u_start));
    rs_ClassBracketed set = rs_ClassBracketed_make(
        rs_Span_new(start, parser_pos(p)), negated,
        rs_ClassSet_union_(empty_inner));
    *out_set   = set;
    *out_union = union_;
    return true;
}

static bool parser_maybe_parse_ascii_class(ResharpParser *p, bool *have,
                                           rs_ClassAscii *out)
{
    *have = false;
    n00b_require(parser_char(p) == '[',
                 "parser_maybe_parse_ascii_class: expected '['");
    rs_Position start = parser_pos(p);
    bool        negated = false;
    if (!parser_bump(p) || parser_char(p) != ':') {
        p->pos = start;
        return true;
    }
    if (!parser_bump(p)) { p->pos = start; return true; }
    if (parser_char(p) == '^') {
        negated = true;
        if (!parser_bump(p)) { p->pos = start; return true; }
    }
    size_t name_start = parser_offset(p);
    while (parser_char(p) != ':' && parser_bump(p)) {}
    if (parser_is_eof(p)) { p->pos = start; return true; }
    size_t name_end = parser_offset(p);
    const char *name = p->pattern + name_start;
    size_t name_len = name_end - name_start;
    if (!parser_bump_if(p, ":]")) { p->pos = start; return true; }
    int kind;
    if (!rs_ClassAsciiKind_from_name(name, name_len, &kind)) {
        p->pos = start;
        return true;
    }
    *out  = rs_ClassAscii_make(rs_Span_new(start, parser_pos(p)), kind, negated);
    *have = true;
    return true;
}

// ---------------------------------------------------------------------------
// max_concat_length / expanded_ast_size — AST metrics.
// ---------------------------------------------------------------------------

size_t max_concat_length(const ast_Ast *ast)
{
    ast_Ast_tag t = ast_Ast_tag_of(ast);
    switch (t) {
        case AST_TAG_EMPTY:
        case AST_TAG_FLAGS:
        case AST_TAG_LITERAL:
        case AST_TAG_DOT:
        case AST_TAG_TOP:
        case AST_TAG_ASSERTION:
        case AST_TAG_CLASS_UNICODE:
        case AST_TAG_CLASS_PERL:
        case AST_TAG_CLASS_BRACKETED:
            return 0;
        case AST_TAG_GROUP:
            return max_concat_length(ast_Group_inner(ast_Ast_as_group(ast)));
        case AST_TAG_COMPLEMENT:
            return max_concat_length(ast_Complement_inner(ast_Ast_as_complement(ast)));
        case AST_TAG_LOOKAROUND:
            return max_concat_length(ast_Lookaround_inner(ast_Ast_as_lookaround(ast)));
        case AST_TAG_REPETITION:
            return max_concat_length(ast_Repetition_inner(ast_Ast_as_repetition(ast)));
        case AST_TAG_CONCAT: {
            const ast_Concat *c = ast_Ast_as_concat(ast);
            size_t n = ast_Concat_count(c);
            size_t maxc = 0;
            for (size_t i = 0; i < n; i++) {
                size_t v = max_concat_length(ast_Concat_get(c, i));
                if (v > maxc) maxc = v;
            }
            return n > maxc ? n : maxc;
        }
        case AST_TAG_ALTERNATION: {
            const ast_Alternation *a = ast_Ast_as_alternation(ast);
            size_t n = ast_Alternation_count(a);
            size_t maxc = 0;
            for (size_t i = 0; i < n; i++) {
                size_t v = max_concat_length(ast_Alternation_get(a, i));
                if (v > maxc) maxc = v;
            }
            return maxc;
        }
        case AST_TAG_INTERSECTION: {
            const ast_Intersection *ii = ast_Ast_as_intersection(ast);
            size_t n = ast_Intersection_count(ii);
            size_t maxc = 0;
            for (size_t i = 0; i < n; i++) {
                size_t v = max_concat_length(ast_Intersection_get(ii, i));
                if (v > maxc) maxc = v;
            }
            return maxc;
        }
    }
    return 0;
}

static uint64_t saturating_add_u64(uint64_t a, uint64_t b)
{
    uint64_t s = a + b;
    return s < a ? UINT64_MAX : s;
}
static uint64_t saturating_mul_u64(uint64_t a, uint64_t b)
{
    if (a == 0 || b == 0) return 0;
    if (a > UINT64_MAX / b) return UINT64_MAX;
    return a * b;
}
static uint64_t min_u64(uint64_t a, uint64_t b) { return a < b ? a : b; }
static uint64_t max_u64(uint64_t a, uint64_t b) { return a > b ? a : b; }

static uint64_t expanded_go(const ast_Ast *ast, uint64_t limit);

static uint64_t expanded_sum_concat(const ast_Concat *c, uint64_t limit)
{
    size_t   n     = ast_Concat_count(c);
    uint64_t total = 0;
    for (size_t i = 0; i < n; i++) {
        total = saturating_add_u64(total, expanded_go(ast_Concat_get(c, i), limit));
        if (total >= limit) return limit;
    }
    return total;
}

static uint64_t expanded_sum_alt(const ast_Alternation *a, uint64_t limit)
{
    size_t   n     = ast_Alternation_count(a);
    uint64_t total = 0;
    for (size_t i = 0; i < n; i++) {
        total = saturating_add_u64(total, expanded_go(ast_Alternation_get(a, i), limit));
        if (total >= limit) return limit;
    }
    return total;
}

static uint64_t expanded_sum_inter(const ast_Intersection *ii, uint64_t limit)
{
    size_t   n     = ast_Intersection_count(ii);
    uint64_t total = 0;
    for (size_t i = 0; i < n; i++) {
        total = saturating_add_u64(total, expanded_go(ast_Intersection_get(ii, i), limit));
        if (total >= limit) return limit;
    }
    return total;
}

static uint64_t expanded_go(const ast_Ast *ast, uint64_t limit)
{
    ast_Ast_tag t = ast_Ast_tag_of(ast);
    switch (t) {
        case AST_TAG_EMPTY:
        case AST_TAG_FLAGS:
        case AST_TAG_LITERAL:
        case AST_TAG_DOT:
        case AST_TAG_TOP:
        case AST_TAG_ASSERTION:
        case AST_TAG_CLASS_UNICODE:
        case AST_TAG_CLASS_PERL:
        case AST_TAG_CLASS_BRACKETED:
            return 1;
        case AST_TAG_GROUP:
            return min_u64(saturating_add_u64(
                expanded_go(ast_Group_inner(ast_Ast_as_group(ast)), limit), 1), limit);
        case AST_TAG_COMPLEMENT:
            return min_u64(saturating_add_u64(
                expanded_go(ast_Complement_inner(ast_Ast_as_complement(ast)), limit), 1), limit);
        case AST_TAG_LOOKAROUND:
            return min_u64(saturating_add_u64(
                expanded_go(ast_Lookaround_inner(ast_Ast_as_lookaround(ast)), limit), 1), limit);
        case AST_TAG_CONCAT:
            return expanded_sum_concat(ast_Ast_as_concat(ast), limit);
        case AST_TAG_ALTERNATION:
            return expanded_sum_alt(ast_Ast_as_alternation(ast), limit);
        case AST_TAG_INTERSECTION:
            return expanded_sum_inter(ast_Ast_as_intersection(ast), limit);
        case AST_TAG_REPETITION: {
            const ast_Repetition *r = ast_Ast_as_repetition(ast);
            uint64_t body   = expanded_go(ast_Repetition_inner(r), limit);
            uint64_t factor = 0;
            ast_RepetitionKind_tag rk = ast_Repetition_op_kind_tag(r);
            if      (rk == AST_REPETITION_ZERO_OR_ONE)  factor = 2;
            else if (rk == AST_REPETITION_ZERO_OR_MORE) factor = 2;
            else if (rk == AST_REPETITION_ONE_OR_MORE)  factor = 2;
            else {
                ast_RepetitionRange_tag rr = ast_Repetition_op_range_tag(r);
                uint32_t lo, hi;
                ast_Repetition_op_range_bounds(r, &lo, &hi);
                if      (rr == AST_REPETITION_RANGE_EXACTLY)  factor = max_u64((uint64_t)lo, 1);
                else if (rr == AST_REPETITION_RANGE_AT_LEAST)
                    factor = saturating_add_u64(max_u64((uint64_t)lo, 1), 1);
                else                                          factor = max_u64((uint64_t)hi, 1);
            }
            return min_u64(saturating_mul_u64(body, factor), limit);
        }
    }
    return 0;
}

uint64_t expanded_ast_size(const ast_Ast *ast, uint64_t limit)
{
    return expanded_go(ast, limit);
}

// ---------------------------------------------------------------------------
// Public top-level entry points.
// ---------------------------------------------------------------------------

NodeId parser_parse_ast(RegexBuilder *tb, const char *pattern, ParseError **err)
{
    ResharpParser *p   = resharp_parser_new(pattern);
    NodeId         out = NODE_ID_BOT;
    ParseError     tmp;
    if (!parser_parse(p, tb, &out, &tmp)) {
        *err  = n00b_alloc(ParseError);
        **err = tmp;
        resharp_parser_free(p);
        return out;
    }
    *err = nullptr;
    resharp_parser_free(p);
    return out;
}

bool resharp_parser_parse_ast(RegexBuilder *tb, const char *pattern,
                              NodeId *out_node)
{
    ParseError *err = nullptr;
    NodeId      out = parser_parse_ast(tb, pattern, &err);
    if (err != nullptr) {
        ParseError_free(err);
        if (out_node != nullptr) *out_node = NODE_ID_BOT;
        return false;
    }
    if (out_node != nullptr) *out_node = out;
    return true;
}

NodeId resharp_parse_ast(RegexBuilder *tb, const char *pattern, int *err_out)
{
    ParseError *err = nullptr;
    NodeId      out = parser_parse_ast(tb, pattern, &err);
    if (err != nullptr) {
        ParseError_free(err);
        if (err_out != nullptr) *err_out = 1;
        return NODE_ID_BOT;
    }
    if (err_out != nullptr) *err_out = 0;
    return out;
}

NodeId parser_parse_ast_with(RegexBuilder *tb, const char *pattern,
                             const PatternFlags *flags, ParseError **err)
{
    ResharpParser *p   = resharp_parser_with_flags_alloc(pattern, flags,
                                                          regex_builder_allocator(tb));
    NodeId         out = NODE_ID_BOT;
    ParseError     tmp;
    if (!parser_parse(p, tb, &out, &tmp)) {
        *err  = n00b_alloc(ParseError);
        **err = tmp;
        resharp_parser_free(p);
        return out;
    }
    *err = nullptr;
    resharp_parser_free(p);
    return out;
}

ast_Ast *parser_parse_to_ast(const char *pattern, ParseError **err)
{
    ResharpParser *p   = resharp_parser_new(pattern);
    ast_Ast       *out = nullptr;
    ParseError     tmp;
    if (!parser_parse_inner(p, &out, &tmp)) {
        *err  = n00b_alloc(ParseError);
        **err = tmp;
        resharp_parser_free(p);
        return nullptr;
    }
    *err = nullptr;
    resharp_parser_free(p);
    return out;
}

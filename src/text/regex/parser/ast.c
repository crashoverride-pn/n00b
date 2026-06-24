// Regex AST — translated from resharp-c's `src/parser/ast.c`.  Tracks
// upstream Rust `regex_syntax::ast` (and parser.c's namespaced
// `ast_*` / `rs_*` view of it).  Containers, allocator, panic, and
// require primitives go through n00b; algorithm flow stays close to
// upstream.

#include "n00b.h"
#include "core/alloc.h"
#include "util/assert.h"
#include "util/panic.h"

#include "internal/regex/ast.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdckdint.h>
#include <string.h> // memcpy / memset / memmove (D13)

// ---------------------------------------------------------------------------
// External forward declarations (resolved cross-file).
// These mirror what the Rust code pulls from `regex_syntax::ast` and the
// span/clone helpers we'd implement against those opaque types.
// ---------------------------------------------------------------------------

// Borrowed accessors on the opaque external types.  We only need Span on
// Literal/ClassUnicode/ClassPerl/ClassBracketed to implement ast_span().
extern const Span *literal_span(const Literal *self);
extern const Span *class_unicode_span(const ClassUnicode *self);
extern const Span *class_perl_span(const ClassPerl *self);
extern const Span *class_bracketed_span(const ClassBracketed *self);

// Span clone (used by `Ast::group` when constructing Lookaround/Complement
// from a Group).  The Rust code copies via #[derive(Clone)].
extern Span *span_clone(const Span *self);

// LookaroundKind clone — kind is `Clone` in Rust.  Trivial here.
static inline LookaroundKind lookaround_kind_clone(LookaroundKind k) { return k; }

// ---------------------------------------------------------------------------
// Tiny helpers
// ---------------------------------------------------------------------------

[[noreturn]] static inline void ast_capacity_overflow(void)
{
    n00b_panic("ast.c: capacity overflow");
}

static inline size_t safe_mul_sz(size_t a, size_t b)
{
    size_t r;
    if (ckd_mul(&r, a, b)) {
        ast_capacity_overflow();
    }
    return r;
}

// `Box::new(span)` aborts on OOM in Rust.  Our wrapper enforces the
// ownership-transfer contract: the incoming pointer must be non-null.
static inline Span *box_span(Span *value) {
    n00b_require(value != nullptr, "box_span: span");
    return value;
}

// Local replacement for libc strlen — `<string.h>` runtime fns are out of
// scope per § 15(C).  Used only on caller-owned NUL-terminated input.
static inline size_t cstr_len(const char *s) {
    const char *p = s;
    while (*p) ++p;
    return (size_t)(p - s);
}

// Geometric-grow for a typed `T data[]` with `len` / `cap` book-keeping.
// Allocates a new buffer at the requested capacity, copies `old_len`
// elements, and frees the old buffer (D13 permits direct memcpy).
#define grow_buf(T, alloc, p_data, old_cap_lvalue, old_len, new_cap)    \
    do {                                                                \
        size_t _gb_nc = (new_cap);                                      \
        T *_gb_new = n00b_alloc_array_with_opts(T, _gb_nc,              \
            &(n00b_alloc_opts_t){.allocator = (alloc)});                \
        if ((old_len) > 0 && *(p_data) != nullptr) {                    \
            memcpy(_gb_new, *(p_data),                                  \
                   safe_mul_sz((old_len), sizeof(T)));                  \
        }                                                               \
        if (*(p_data) != nullptr) {                                     \
            n00b_free(*(p_data));                                       \
        }                                                               \
        *(p_data) = _gb_new;                                            \
        (old_cap_lvalue) = _gb_nc;                                      \
    } while (0)

// ---------------------------------------------------------------------------
// Static-string copy helper for error_kind_display — replaces the libc
// snprintf path.  Returns bytes written (excluding NUL) or buflen-1 on
// truncation, matching the resharp-c contract.
// ---------------------------------------------------------------------------

static int copy_msg(char *buf, size_t buflen, const char *msg) {
    size_t mlen = cstr_len(msg);
    if (buflen == 0) {
        return (int)mlen;
    }
    if (mlen >= buflen) {
        memcpy(buf, msg, buflen - 1);
        buf[buflen - 1] = '\0';
        return (int)(buflen - 1);
    }
    memcpy(buf, msg, mlen);
    buf[mlen] = '\0';
    return (int)mlen;
}

// Render `prefix` then `value` as decimal then `suffix` into buf.
// Used by the two ErrorKind variants that carry a uint32_t (NEST_LIMIT and
// CAPTURE_LIMIT).  Returns bytes written / buflen-1 like copy_msg.
static int format_u32_msg(char *buf, size_t buflen,
                          const char *prefix, uint32_t value,
                          const char *suffix) {
    // Render into a stack buffer, then splice.  uint32_t fits in 10 digits.
    char digits[16];
    size_t dlen = 0;
    if (value == 0) {
        digits[dlen++] = '0';
    } else {
        char tmp[16];
        size_t tlen = 0;
        uint32_t v = value;
        while (v) {
            tmp[tlen++] = (char)('0' + (v % 10));
            v /= 10;
        }
        while (tlen) {
            digits[dlen++] = tmp[--tlen];
        }
    }

    size_t plen = cstr_len(prefix);
    size_t slen = cstr_len(suffix);
    size_t total = plen + dlen + slen;

    if (buflen == 0) {
        return (int)total;
    }
    if (total >= buflen) {
        // Truncate.  Copy as much as fits, then NUL-terminate.
        size_t room = buflen - 1;
        size_t off  = 0;
        size_t cp;
        cp = (room - off < plen) ? (room - off) : plen;
        memcpy(buf + off, prefix, cp);
        off += cp;
        if (off < room) {
            cp = (room - off < dlen) ? (room - off) : dlen;
            memcpy(buf + off, digits, cp);
            off += cp;
        }
        if (off < room) {
            cp = (room - off < slen) ? (room - off) : slen;
            memcpy(buf + off, suffix, cp);
            off += cp;
        }
        buf[off] = '\0';
        return (int)off;
    }
    memcpy(buf, prefix, plen);
    memcpy(buf + plen, digits, dlen);
    memcpy(buf + plen + dlen, suffix, slen);
    buf[total] = '\0';
    return (int)total;
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

const ErrorKind *error_kind(const Error *self) {
    n00b_require(self != nullptr, "error_kind: self");
    return &self->kind;
}

const char *error_pattern(const Error *self) {
    n00b_require(self != nullptr, "error_pattern: self");
    return self->pattern.data;
}

const Span *error_span(const Error *self) {
    n00b_require(self != nullptr, "error_span: self");
    return self->span;
}

const Span *error_auxiliary_span(const Error *self) {
    n00b_require(self != nullptr, "error_auxiliary_span: self");
    switch (self->kind.tag) {
        case ERROR_KIND_FLAG_DUPLICATE:
            return self->kind.u.flag_duplicate_original;
        case ERROR_KIND_FLAG_REPEATED_NEGATION:
            return self->kind.u.flag_repeated_negation_original;
        case ERROR_KIND_GROUP_NAME_DUPLICATE:
            return self->kind.u.group_name_duplicate_original;
        default:
            return nullptr;
    }
}

int error_kind_display(const ErrorKind *self, char *buf, size_t buflen) {
    n00b_require(self != nullptr, "error_kind_display: self");
    switch (self->tag) {
        case ERROR_KIND_CAPTURE_LIMIT_EXCEEDED:
            return format_u32_msg(buf, buflen,
                "exceeded the maximum number of capturing groups (",
                UINT32_MAX, ")");
        case ERROR_KIND_CLASS_ESCAPE_INVALID:
            return copy_msg(buf, buflen,
                "invalid escape sequence found in character class");
        case ERROR_KIND_CLASS_RANGE_INVALID:
            return copy_msg(buf, buflen,
                "invalid character class range, the start must be <= the end");
        case ERROR_KIND_CLASS_RANGE_LITERAL:
            return copy_msg(buf, buflen,
                "invalid range boundary, must be a literal");
        case ERROR_KIND_CLASS_UNCLOSED:
            return copy_msg(buf, buflen, "unclosed character class");
        case ERROR_KIND_DECIMAL_EMPTY:
            return copy_msg(buf, buflen, "decimal literal empty");
        case ERROR_KIND_DECIMAL_INVALID:
            return copy_msg(buf, buflen, "decimal literal invalid");
        case ERROR_KIND_ESCAPE_HEX_EMPTY:
            return copy_msg(buf, buflen, "hexadecimal literal empty");
        case ERROR_KIND_ESCAPE_HEX_INVALID:
            return copy_msg(buf, buflen,
                "hexadecimal literal is not a Unicode scalar value");
        case ERROR_KIND_ESCAPE_HEX_INVALID_DIGIT:
            return copy_msg(buf, buflen, "invalid hexadecimal digit");
        case ERROR_KIND_ESCAPE_UNEXPECTED_EOF:
            return copy_msg(buf, buflen,
                "incomplete escape sequence, "
                "reached end of pattern prematurely");
        case ERROR_KIND_ESCAPE_UNRECOGNIZED:
            return copy_msg(buf, buflen, "unrecognized escape sequence");
        case ERROR_KIND_FLAG_DANGLING_NEGATION:
            return copy_msg(buf, buflen, "dangling flag negation operator");
        case ERROR_KIND_FLAG_DUPLICATE:
            return copy_msg(buf, buflen, "duplicate flag");
        case ERROR_KIND_FLAG_REPEATED_NEGATION:
            return copy_msg(buf, buflen, "flag negation operator repeated");
        case ERROR_KIND_FLAG_UNEXPECTED_EOF:
            return copy_msg(buf, buflen, "expected flag but got end of regex");
        case ERROR_KIND_FLAG_UNRECOGNIZED:
            return copy_msg(buf, buflen, "unrecognized flag");
        case ERROR_KIND_GROUP_NAME_DUPLICATE:
            return copy_msg(buf, buflen, "duplicate capture group name");
        case ERROR_KIND_GROUP_NAME_EMPTY:
            return copy_msg(buf, buflen, "empty capture group name");
        case ERROR_KIND_GROUP_NAME_INVALID:
            return copy_msg(buf, buflen, "invalid capture group character");
        case ERROR_KIND_GROUP_NAME_UNEXPECTED_EOF:
            return copy_msg(buf, buflen, "unclosed capture group name");
        case ERROR_KIND_GROUP_UNCLOSED:
            return copy_msg(buf, buflen, "unclosed group");
        case ERROR_KIND_GROUP_UNOPENED:
            return copy_msg(buf, buflen, "unopened group");
        case ERROR_KIND_NEST_LIMIT_EXCEEDED:
            return format_u32_msg(buf, buflen,
                "exceed the maximum number of nested parentheses/brackets (",
                self->u.nest_limit_exceeded, ")");
        case ERROR_KIND_REPETITION_COUNT_INVALID:
            return copy_msg(buf, buflen,
                "invalid repetition count range, the start must be <= the end");
        case ERROR_KIND_REPETITION_COUNT_DECIMAL_EMPTY:
            return copy_msg(buf, buflen,
                "repetition quantifier expects a valid decimal");
        case ERROR_KIND_REPETITION_COUNT_UNCLOSED:
            return copy_msg(buf, buflen, "unclosed counted repetition");
        case ERROR_KIND_REPETITION_MISSING:
            return copy_msg(buf, buflen, "repetition operator missing expression");
        case ERROR_KIND_SPECIAL_WORD_BOUNDARY_UNCLOSED:
            return copy_msg(buf, buflen,
                "special word boundary assertion is either unclosed or "
                "contains an invalid character");
        case ERROR_KIND_SPECIAL_WORD_BOUNDARY_UNRECOGNIZED:
            return copy_msg(buf, buflen,
                "unrecognized special word boundary assertion, "
                "valid choices are: start, end, start-half or end-half");
        case ERROR_KIND_SPECIAL_WORD_OR_REPETITION_UNEXPECTED_EOF:
            return copy_msg(buf, buflen,
                "found either the beginning of a special word boundary or a "
                "bounded repetition on a \\b with an opening brace, but no "
                "closing brace");
        case ERROR_KIND_UNICODE_CLASS_INVALID:
            return copy_msg(buf, buflen, "invalid Unicode character class");
        case ERROR_KIND_UNSUPPORTED_BACKREFERENCE:
            return copy_msg(buf, buflen, "backreferences are not supported");
        case ERROR_KIND_UNSUPPORTED_LOOK_AROUND:
            return copy_msg(buf, buflen,
                "look-around, including look-ahead and look-behind, "
                "is not supported");
        case ERROR_KIND_UNSUPPORTED_RESHARP_REGEX:
            return copy_msg(buf, buflen, "this pattern is not supported");
        case ERROR_KIND_UNSUPPORTED_LAZY_QUANTIFIER:
            return copy_msg(buf, buflen, "lazy quantifiers are not supported");
        case ERROR_KIND_COMPLEMENT_GROUP_EXPECTED:
            return copy_msg(buf, buflen,
                "expected ( after ~ for complement group");
    }
    n00b_panic("error_kind_display: invalid ErrorKind tag «#»",
               (int64_t)self->tag);
}

// ---------------------------------------------------------------------------
// Ast constructors
// ---------------------------------------------------------------------------

Ast ast_empty(Span *span) {
    n00b_require(span != nullptr, "ast_empty: span");
    return (Ast){ .tag = AST_EMPTY, .u.empty = box_span(span) };
}

Ast ast_flags(SetFlags *e) {
    n00b_require(e != nullptr, "ast_flags: e");
    return (Ast){ .tag = AST_FLAGS, .u.flags = e };
}

Ast ast_literal(Literal *e) {
    n00b_require(e != nullptr, "ast_literal: e");
    return (Ast){ .tag = AST_LITERAL, .u.literal = e };
}

Ast ast_dot(Span *span) {
    n00b_require(span != nullptr, "ast_dot: span");
    return (Ast){ .tag = AST_DOT, .u.dot = box_span(span) };
}

Ast ast_top(Span *span) {
    n00b_require(span != nullptr, "ast_top: span");
    return (Ast){ .tag = AST_TOP, .u.top = box_span(span) };
}

Ast ast_assertion(Assertion *e) {
    n00b_require(e != nullptr, "ast_assertion: e");
    return (Ast){ .tag = AST_ASSERTION, .u.assertion = e };
}

Ast ast_class_unicode(ClassUnicode *e) {
    n00b_require(e != nullptr, "ast_class_unicode: e");
    return (Ast){ .tag = AST_CLASS_UNICODE, .u.class_unicode = e };
}

Ast ast_class_perl(ClassPerl *e) {
    n00b_require(e != nullptr, "ast_class_perl: e");
    return (Ast){ .tag = AST_CLASS_PERL, .u.class_perl = e };
}

Ast ast_class_bracketed(ClassBracketed *e) {
    n00b_require(e != nullptr, "ast_class_bracketed: e");
    return (Ast){ .tag = AST_CLASS_BRACKETED, .u.class_bracketed = e };
}

Ast ast_repetition(Repetition *e) {
    n00b_require(e != nullptr, "ast_repetition: e");
    return (Ast){ .tag = AST_REPETITION, .u.repetition = e };
}

Ast ast_alternation(Alternation *e) {
    n00b_require(e != nullptr, "ast_alternation: e");
    return (Ast){ .tag = AST_ALTERNATION, .u.alternation = e };
}

Ast ast_concat(Concat *e) {
    n00b_require(e != nullptr, "ast_concat: e");
    return (Ast){ .tag = AST_CONCAT, .u.concat = e };
}

Ast ast_intersection(Intersection *e) {
    n00b_require(e != nullptr, "ast_intersection: e");
    return (Ast){ .tag = AST_INTERSECTION, .u.intersection = e };
}

Ast ast_complement(Complement *e) {
    n00b_require(e != nullptr, "ast_complement: e");
    return (Ast){ .tag = AST_COMPLEMENT, .u.complement = e };
}

Ast ast_lookaround(Lookaround *e) {
    n00b_require(e != nullptr, "ast_lookaround: e");
    return (Ast){ .tag = AST_LOOKAROUND, .u.lookaround = e };
}

// `Ast::group` dispatches based on `e.kind` — for Lookaround and Complement
// variants it rewrites to a Lookaround/Complement AST instead.
Ast ast_group(Group *e) {
    n00b_require(e != nullptr, "ast_group: e");
    switch (e->kind.selector) {
        case typehash(uint32_t):
        case typehash(GroupKind_capture_name_t):
        case typehash(Flags *):
            return (Ast){ .tag = AST_GROUP, .u.group = e };
        case typehash(LookaroundKind): {
            // Rust `Ast::group` *moves* `e.span` and `e.ast` into the new
            // Lookaround.  Naively copying the pointers leaves `e->span` and
            // `e->ast` aliased through the new node, so when the caller
            // frees `e` (per the documented "consumes/owns the argument"
            // contract) the Lookaround dangles.  Fix: deep-clone the Span
            // via the existing `span_clone`, and transfer the `Ast *`
            // pointer with explicit move semantics (null out e->ast so the
            // source no longer aliases the new owner).
            Lookaround *look = n00b_alloc(Lookaround);
            look->kind = lookaround_kind_clone(n00b_variant_get(e->kind, LookaroundKind));
            look->span = span_clone(e->span);
            look->ast  = e->ast;
            e->ast     = nullptr;
            return ast_lookaround(look);
        }
        default: {
            // COMPLEMENT (empty selector, == 0).  Same fix as the LOOKAROUND
            // branch — deep-clone the Span and move the Ast pointer with an
            // explicit null-out.
            Complement *g = n00b_alloc(Complement);
            g->span = span_clone(e->span);
            g->ast  = e->ast;
            e->ast  = nullptr;
            return ast_complement(g);
        }
    }
    n00b_unreachable();
}

// ---------------------------------------------------------------------------
// Ast accessors
// ---------------------------------------------------------------------------

const Span *ast_span(const Ast *self) {
    n00b_require(self != nullptr, "ast_span: self");
    switch (self->tag) {
        case AST_EMPTY:           return self->u.empty;
        case AST_FLAGS:           return self->u.flags->span;
        case AST_LITERAL:         return literal_span(self->u.literal);
        case AST_DOT:             return self->u.dot;
        case AST_TOP:             return self->u.top;
        case AST_ASSERTION:       return self->u.assertion->span;
        case AST_CLASS_UNICODE:   return class_unicode_span(self->u.class_unicode);
        case AST_CLASS_PERL:      return class_perl_span(self->u.class_perl);
        case AST_CLASS_BRACKETED: return class_bracketed_span(self->u.class_bracketed);
        case AST_REPETITION:      return self->u.repetition->span;
        case AST_GROUP:           return self->u.group->span;
        case AST_ALTERNATION:     return self->u.alternation->span;
        case AST_CONCAT:          return self->u.concat->span;
        case AST_INTERSECTION:    return self->u.intersection->span;
        case AST_COMPLEMENT:      return self->u.complement->span;
        case AST_LOOKAROUND:      return self->u.lookaround->span;
    }
    n00b_panic("ast_span: invalid AstTag «#»", (int64_t)self->tag);
}

bool ast_is_empty(const Ast *self) {
    n00b_require(self != nullptr, "ast_is_empty: self");
    return self->tag == AST_EMPTY;
}

bool ast_has_subexprs(const Ast *self) {
    n00b_require(self != nullptr, "ast_has_subexprs: self");
    switch (self->tag) {
        case AST_EMPTY:
        case AST_FLAGS:
        case AST_LITERAL:
        case AST_DOT:
        case AST_TOP:
        case AST_ASSERTION:
        case AST_CLASS_UNICODE:
        case AST_CLASS_PERL:
            return false;
        case AST_CLASS_BRACKETED:
        case AST_REPETITION:
        case AST_GROUP:
        case AST_ALTERNATION:
        case AST_INTERSECTION:
        case AST_LOOKAROUND:
        case AST_COMPLEMENT:
        case AST_CONCAT:
            return true;
    }
    n00b_panic("ast_has_subexprs: invalid AstTag «#»", (int64_t)self->tag);
}

// ---------------------------------------------------------------------------
// Alternation / Concat / Intersection collapse
// ---------------------------------------------------------------------------

// NOTE: the Rust `into_ast` consumes `self` by value; here it consumes the
// pointed-to value (clearing fields) and the caller continues to own the
// outer storage.

static Ast vec_collapse_into_ast(AstVec *asts, Span *span,
                                 Ast (*build)(void *), void *boxed_self) {
    n00b_require(asts != nullptr, "vec_collapse_into_ast: asts");
    // Enforce the Vec invariant before any data[] access.  A malformed
    // AstVec with `len > 0 && data == NULL` would otherwise crash with a
    // null deref below.
    n00b_require(asts->len == 0 || asts->data != nullptr,
                 "vec_collapse_into_ast: AstVec invariant violated");
    if (asts->len == 0) {
        // Rust `into_ast` *moves* `self.span` into `Ast::empty(self.span)`.
        // Aliasing the pointer means the caller's `*self` (still owned by
        // the caller) points at a Span now also referenced by the returned
        // Ast — freeing either side dangles the other.  Deep-clone via the
        // existing `span_clone` so the returned AST_EMPTY is fully
        // independent.
        return ast_empty(span_clone(span));
    }
    if (asts->len == 1) {
        Ast only = asts->data[0];
        // Drop the vec contents — the single element has been taken.
        n00b_free(asts->data);
        asts->data = nullptr;
        asts->len  = 0;
        asts->cap  = 0;
        return only;
    }
    return build(boxed_self);
}

static Ast build_alternation(void *p) {
    return ast_alternation((Alternation *)p);
}
static Ast build_concat(void *p) {
    return ast_concat((Concat *)p);
}
static Ast build_intersection(void *p) {
    return ast_intersection((Intersection *)p);
}

Ast alternation_into_ast(Alternation *self) {
    n00b_require(self != nullptr, "alternation_into_ast: self");
    return vec_collapse_into_ast(&self->asts, self->span,
                                 build_alternation, self);
}

Ast concat_into_ast(Concat *self) {
    n00b_require(self != nullptr, "concat_into_ast: self");
    return vec_collapse_into_ast(&self->asts, self->span,
                                 build_concat, self);
}

Ast intersection_into_ast(Intersection *self) {
    n00b_require(self != nullptr, "intersection_into_ast: self");
    return vec_collapse_into_ast(&self->asts, self->span,
                                 build_intersection, self);
}

Ast complement_into_ast(Complement *self) {
    n00b_require(self != nullptr, "complement_into_ast: self");
    return ast_complement(self);
}

Ast lookaround_into_ast(Lookaround *self) {
    n00b_require(self != nullptr, "lookaround_into_ast: self");
    return ast_lookaround(self);
}

// ---------------------------------------------------------------------------
// RepetitionRange
// ---------------------------------------------------------------------------

bool RepetitionRange_is_valid(const RepetitionRange *self) {
    n00b_require(self != nullptr, "RepetitionRange_is_valid: self");
    if (self->tag == REPETITION_RANGE_BOUNDED && self->m > self->n) {
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Group
// ---------------------------------------------------------------------------

const Flags *group_flags(const Group *self) {
    n00b_require(self != nullptr, "group_flags: self");
    if (n00b_variant_is_type(self->kind, Flags *)) {
        return n00b_variant_get(self->kind, Flags *);
    }
    return nullptr;
}

bool group_is_capturing(const Group *self) {
    n00b_require(self != nullptr, "group_is_capturing: self");
    switch (self->kind.selector) {
        case typehash(uint32_t):
        case typehash(GroupKind_capture_name_t):
            return true;
        case typehash(Flags *):
        case typehash(LookaroundKind):
        case 0: // COMPLEMENT (empty selector)
            return false;
    }
    n00b_panic("group_is_capturing: invalid GroupKind tag «#»",
               (int64_t)self->kind.selector);
}

bool group_capture_index(const Group *self, uint32_t *out) {
    n00b_require(self != nullptr, "group_capture_index: self");
    n00b_require(out != nullptr, "group_capture_index: out");
    switch (self->kind.selector) {
        case typehash(uint32_t):
            *out = n00b_variant_get(self->kind, uint32_t);
            return true;
        case typehash(GroupKind_capture_name_t):
            *out = n00b_variant_get(self->kind, GroupKind_capture_name_t).name.index;
            return true;
        case typehash(Flags *):
        case typehash(LookaroundKind):
        case 0: // COMPLEMENT (empty selector)
            return false;
    }
    n00b_panic("group_capture_index: invalid GroupKind tag «#»",
               (int64_t)self->kind.selector);
}

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

static bool flags_item_kind_eq(const FlagsItemKind *a, const FlagsItemKind *b) {
    if (a->tag != b->tag) return false;
    if (a->tag == FLAGS_ITEM_KIND_FLAG) return a->flag == b->flag;
    return true; // Negation == Negation
}

bool flags_add_item(Flags *self, FlagsItem item, size_t *out_index) {
    n00b_require(self != nullptr, "flags_add_item: self");
    n00b_require(self->items.len == 0 || self->items.data != nullptr,
                 "flags_add_item: FlagsItemVec invariant violated");
    for (size_t i = 0; i < self->items.len; ++i) {
        if (flags_item_kind_eq(&self->items.data[i].kind, &item.kind)) {
            if (out_index) *out_index = i;
            return false;
        }
    }
    // Push back; grow geometrically.  Rust `Vec::push` panics on alloc
    // failure — n00b_alloc_array does the same via the runtime allocator,
    // and the size computation goes through ckd_mul (overflow → panic).
    if (self->items.len == self->items.cap) {
        size_t new_cap = self->items.cap ? safe_mul_sz(self->items.cap, 2) : 4;
        grow_buf(FlagsItem, nullptr, &self->items.data, self->items.cap,
                 self->items.len, new_cap);
    }
    self->items.data[self->items.len++] = item;
    return true;
}

bool flags_item_kind_is_negation(const FlagsItemKind *self) {
    n00b_require(self != nullptr, "flags_item_kind_is_negation: self");
    return self->tag == FLAGS_ITEM_KIND_NEGATION;
}

int flags_flag_state(const Flags *self, Flag flag, bool *out) {
    n00b_require(self != nullptr, "flags_flag_state: self");
    n00b_require(self->items.len == 0 || self->items.data != nullptr,
                 "flags_flag_state: FlagsItemVec invariant violated");
    bool negated = false;
    for (size_t i = 0; i < self->items.len; ++i) {
        const FlagsItem *x = &self->items.data[i];
        switch (x->kind.tag) {
            case FLAGS_ITEM_KIND_NEGATION:
                negated = true;
                break;
            case FLAGS_ITEM_KIND_FLAG:
                if (x->kind.flag == flag) {
                    if (out) *out = !negated;
                    return 1;
                }
                break;
        }
    }
    return 0;
}

// ===========================================================================
// ast_<Type>_<method> namespaced API.
//
// These are the Rust impl-block methods used by parser.c.  The call sites
// refer to types as ast_Concat / ast_Group / etc.; this section uses the
// parallel layouts declared in the header whose by-value sizes match the
// stub footprints (so the C ABI lines up across translation units).
// ===========================================================================

// ast_Ast — internal definition.  Opaque outside this TU.
struct ast_Ast {
    ast_Ast_tag tag;
    union [[n00b::raw_union]] {
        rs_Span           empty;          // AST_TAG_EMPTY
        rs_Span           dot;            // AST_TAG_DOT
        rs_Span           top;            // AST_TAG_TOP
        rs_Literal        literal;        // AST_TAG_LITERAL
        rs_ClassPerl      class_perl;
        rs_ClassUnicode   class_unicode;
        rs_ClassBracketed class_bracketed;
        ast_Assertion     assertion;
        ast_SetFlags      flags;
        ast_Repetition    repetition;
        ast_Group         group;
        ast_Alternation   alternation;
        ast_Concat        concat;
        ast_Intersection  intersection;
        ast_Complement    complement;
        ast_Lookaround    lookaround;
    } u;
};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static inline ast_Ast *ast_alloc(ast_Ast_tag tag, n00b_allocator_t *allocator) {
    ast_Ast *a = n00b_alloc_with_opts(ast_Ast,
                                       &(n00b_alloc_opts_t){.allocator = allocator});
    a->tag = tag;
    return a;
}

// Geometric vector growth for ast_Ast** lists shared by Concat/Alternation/
// Intersection (all have the same layout).
static void ast_ptrvec_grow(ast_Ast ***data, size_t *cap, size_t needed,
                            n00b_allocator_t *allocator) {
    if (*cap >= needed) return;
    size_t new_cap = *cap ? safe_mul_sz(*cap, 2) : 4;
    while (new_cap < needed) new_cap = safe_mul_sz(new_cap, 2);
    grow_buf(ast_Ast *, allocator, data, *cap, *cap, new_cap);
}

static void ast_flagsitem_grow(ast_FlagsItem **data, size_t *cap, size_t needed,
                               n00b_allocator_t *allocator) {
    if (*cap >= needed) return;
    size_t new_cap = *cap ? safe_mul_sz(*cap, 2) : 4;
    while (new_cap < needed) new_cap = safe_mul_sz(new_cap, 2);
    grow_buf(ast_FlagsItem, allocator, data, *cap, *cap, new_cap);
}

// Free helpers used by ast_Ast_free walking the tree.
static void ast_concat_drop(ast_Concat *c);
static void ast_alternation_drop(ast_Alternation *a);
static void ast_intersection_drop(ast_Intersection *i);
static void ast_group_drop(ast_Group *g);
static void ast_repetition_drop(ast_Repetition *r);
static void ast_complement_drop(ast_Complement *c);
static void ast_lookaround_drop(ast_Lookaround *l);
static void ast_setflags_drop(ast_SetFlags *f);
static void ast_flags_drop(ast_Flags *f);

// ---------------------------------------------------------------------------
// ast_Ast constructors / destructor / accessors
// ---------------------------------------------------------------------------

ast_Ast *ast_Ast_empty_owned(rs_Span span, n00b_allocator_t *allocator) {
    ast_Ast *a = ast_alloc(AST_TAG_EMPTY, allocator);
    a->u.empty = span;
    return a;
}

ast_Ast *ast_Ast_dot_owned(rs_Span span, n00b_allocator_t *allocator) {
    ast_Ast *a = ast_alloc(AST_TAG_DOT, allocator);
    a->u.dot = span;
    return a;
}

ast_Ast *ast_Ast_top_owned(rs_Span span, n00b_allocator_t *allocator) {
    ast_Ast *a = ast_alloc(AST_TAG_TOP, allocator);
    a->u.top = span;
    return a;
}

ast_Ast *ast_Ast_literal_owned(rs_Literal lit, n00b_allocator_t *allocator) {
    ast_Ast *a = ast_alloc(AST_TAG_LITERAL, allocator);
    a->u.literal = lit;
    return a;
}

ast_Ast *ast_Ast_assertion_owned(ast_Assertion x, n00b_allocator_t *allocator) {
    ast_Ast *a = ast_alloc(AST_TAG_ASSERTION, allocator);
    a->u.assertion = x;
    return a;
}

ast_Ast *ast_Ast_class_perl_owned(rs_ClassPerl c, n00b_allocator_t *allocator) {
    ast_Ast *a = ast_alloc(AST_TAG_CLASS_PERL, allocator);
    a->u.class_perl = c;
    return a;
}

ast_Ast *ast_Ast_class_unicode_owned(rs_ClassUnicode c, n00b_allocator_t *allocator) {
    ast_Ast *a = ast_alloc(AST_TAG_CLASS_UNICODE, allocator);
    a->u.class_unicode = c;
    return a;
}

ast_Ast *ast_Ast_class_bracketed_owned(rs_ClassBracketed c, n00b_allocator_t *allocator) {
    ast_Ast *a = ast_alloc(AST_TAG_CLASS_BRACKETED, allocator);
    a->u.class_bracketed = c;
    return a;
}

ast_Ast *ast_Ast_flags_owned(ast_SetFlags f, n00b_allocator_t *allocator) {
    ast_Ast *a = ast_alloc(AST_TAG_FLAGS, allocator);
    a->u.flags = f;
    return a;
}

ast_Ast *ast_Ast_repetition_owned(ast_Repetition r, n00b_allocator_t *allocator) {
    ast_Ast *a = ast_alloc(AST_TAG_REPETITION, allocator);
    a->u.repetition = r;
    return a;
}

// `Ast::group` in Rust dispatches: Lookaround / Complement variants are
// rewritten to dedicated tags; the rest stay as Group.
ast_Ast *ast_Ast_group_owned(ast_Group g, n00b_allocator_t *allocator) {
    if (g.kind_tag == AST_GROUP_KIND_LOOKAROUND) {
        ast_Lookaround look = (ast_Lookaround){
            .kind = g.lookaround_kind,
            .span = g.span,
            .ast  = g.ast,
        };
        // g owns no other heap (lookaround payload is inline)
        ast_Ast *a = ast_alloc(AST_TAG_LOOKAROUND, allocator);
        a->u.lookaround = look;
        return a;
    }
    if (g.kind_tag == AST_GROUP_KIND_COMPLEMENT) {
        ast_Complement c = (ast_Complement){
            .span = g.span,
            .ast  = g.ast,
        };
        ast_Ast *a = ast_alloc(AST_TAG_COMPLEMENT, allocator);
        a->u.complement = c;
        return a;
    }
    ast_Ast *a = ast_alloc(AST_TAG_GROUP, allocator);
    a->u.group = g;
    return a;
}

ast_Ast *ast_Ast_alternation_owned(ast_Alternation x, n00b_allocator_t *allocator) {
    ast_Ast *a = ast_alloc(AST_TAG_ALTERNATION, allocator);
    a->u.alternation = x;
    return a;
}

ast_Ast *ast_Ast_intersection_owned(ast_Intersection x, n00b_allocator_t *allocator) {
    ast_Ast *a = ast_alloc(AST_TAG_INTERSECTION, allocator);
    a->u.intersection = x;
    return a;
}

ast_Ast *ast_Ast_complement_owned(ast_Complement x, n00b_allocator_t *allocator) {
    ast_Ast *a = ast_alloc(AST_TAG_COMPLEMENT, allocator);
    a->u.complement = x;
    return a;
}

ast_Ast *ast_Ast_lookaround_owned(ast_Lookaround x, n00b_allocator_t *allocator) {
    ast_Ast *a = ast_alloc(AST_TAG_LOOKAROUND, allocator);
    a->u.lookaround = x;
    return a;
}

ast_Ast *ast_Ast_concat_owned(ast_Concat x, n00b_allocator_t *allocator) {
    ast_Ast *a = ast_alloc(AST_TAG_CONCAT, allocator);
    a->u.concat = x;
    return a;
}

void ast_Ast_free(ast_Ast *a) {
    if (!a) return;
    switch (a->tag) {
        case AST_TAG_EMPTY:
        case AST_TAG_DOT:
        case AST_TAG_TOP:
        case AST_TAG_LITERAL:
        case AST_TAG_CLASS_PERL:
        case AST_TAG_CLASS_UNICODE:
        case AST_TAG_CLASS_BRACKETED:
        case AST_TAG_ASSERTION:
            break;
        case AST_TAG_FLAGS:        ast_setflags_drop(&a->u.flags); break;
        case AST_TAG_REPETITION:   ast_repetition_drop(&a->u.repetition); break;
        case AST_TAG_GROUP:        ast_group_drop(&a->u.group); break;
        case AST_TAG_ALTERNATION:  ast_alternation_drop(&a->u.alternation); break;
        case AST_TAG_CONCAT:       ast_concat_drop(&a->u.concat); break;
        case AST_TAG_INTERSECTION: ast_intersection_drop(&a->u.intersection); break;
        case AST_TAG_COMPLEMENT:   ast_complement_drop(&a->u.complement); break;
        case AST_TAG_LOOKAROUND:   ast_lookaround_drop(&a->u.lookaround); break;
    }
    n00b_free(a);
}

ast_Ast_tag ast_Ast_tag_of(const ast_Ast *a) {
    n00b_require(a != nullptr, "ast_Ast_tag_of: a");
    return a->tag;
}

const rs_Span *ast_Ast_span(const ast_Ast *a) {
    n00b_require(a != nullptr, "ast_Ast_span: a");
    switch (a->tag) {
        case AST_TAG_EMPTY:           return &a->u.empty;
        case AST_TAG_DOT:             return &a->u.dot;
        case AST_TAG_TOP:             return &a->u.top;
        case AST_TAG_LITERAL:
            // WHY: rs_Literal carries an inline rs_Span; parser.c never
            // asks ast_Ast_span() for a literal in practice (literals come
            // from the rs_Literal_owned path with their own span tracking),
            // so returning nullptr matches resharp-c's behavior.
            return nullptr;
        case AST_TAG_CLASS_PERL:      return nullptr;
        case AST_TAG_CLASS_UNICODE:   return nullptr;
        case AST_TAG_CLASS_BRACKETED: return nullptr;
        case AST_TAG_ASSERTION:       return &a->u.assertion.span;
        case AST_TAG_FLAGS:           return &a->u.flags.span;
        case AST_TAG_REPETITION:      return &a->u.repetition.span;
        case AST_TAG_GROUP:           return &a->u.group.span;
        case AST_TAG_ALTERNATION:     return &a->u.alternation.span;
        case AST_TAG_CONCAT:          return &a->u.concat.span;
        case AST_TAG_INTERSECTION:    return &a->u.intersection.span;
        case AST_TAG_COMPLEMENT:      return &a->u.complement.span;
        case AST_TAG_LOOKAROUND:      return &a->u.lookaround.span;
    }
    n00b_panic("ast_Ast_span: invalid tag «#»", (int64_t)a->tag);
}

rs_Span ast_Ast_span_with_end(const ast_Ast *a, rs_Position end) {
    const rs_Span *s = ast_Ast_span(a);
    rs_Span out = s ? *s : (rs_Span){};
    out.end = end;
    return out;
}

const rs_Literal *ast_Ast_as_literal(const ast_Ast *a) {
    n00b_require(a != nullptr, "ast_Ast_as_literal: a");
    n00b_require(a->tag == AST_TAG_LITERAL, "ast_Ast_as_literal: tag mismatch");
    return &a->u.literal;
}
const rs_ClassPerl *ast_Ast_as_class_perl(const ast_Ast *a) {
    n00b_require(a != nullptr, "ast_Ast_as_class_perl: a");
    n00b_require(a->tag == AST_TAG_CLASS_PERL, "ast_Ast_as_class_perl: tag mismatch");
    return &a->u.class_perl;
}
const rs_ClassUnicode *ast_Ast_as_class_unicode(const ast_Ast *a) {
    n00b_require(a != nullptr, "ast_Ast_as_class_unicode: a");
    n00b_require(a->tag == AST_TAG_CLASS_UNICODE,
                 "ast_Ast_as_class_unicode: tag mismatch");
    return &a->u.class_unicode;
}
const rs_ClassBracketed *ast_Ast_as_class_bracketed(const ast_Ast *a) {
    n00b_require(a != nullptr, "ast_Ast_as_class_bracketed: a");
    n00b_require(a->tag == AST_TAG_CLASS_BRACKETED,
                 "ast_Ast_as_class_bracketed: tag mismatch");
    return &a->u.class_bracketed;
}
const ast_Group *ast_Ast_as_group(const ast_Ast *a) {
    n00b_require(a != nullptr, "ast_Ast_as_group: a");
    n00b_require(a->tag == AST_TAG_GROUP, "ast_Ast_as_group: tag mismatch");
    return &a->u.group;
}
const ast_Concat *ast_Ast_as_concat(const ast_Ast *a) {
    n00b_require(a != nullptr, "ast_Ast_as_concat: a");
    n00b_require(a->tag == AST_TAG_CONCAT, "ast_Ast_as_concat: tag mismatch");
    return &a->u.concat;
}
const ast_Alternation *ast_Ast_as_alternation(const ast_Ast *a) {
    n00b_require(a != nullptr, "ast_Ast_as_alternation: a");
    n00b_require(a->tag == AST_TAG_ALTERNATION,
                 "ast_Ast_as_alternation: tag mismatch");
    return &a->u.alternation;
}
const ast_Intersection *ast_Ast_as_intersection(const ast_Ast *a) {
    n00b_require(a != nullptr, "ast_Ast_as_intersection: a");
    n00b_require(a->tag == AST_TAG_INTERSECTION,
                 "ast_Ast_as_intersection: tag mismatch");
    return &a->u.intersection;
}
const ast_Complement *ast_Ast_as_complement(const ast_Ast *a) {
    n00b_require(a != nullptr, "ast_Ast_as_complement: a");
    n00b_require(a->tag == AST_TAG_COMPLEMENT,
                 "ast_Ast_as_complement: tag mismatch");
    return &a->u.complement;
}
const ast_Lookaround *ast_Ast_as_lookaround(const ast_Ast *a) {
    n00b_require(a != nullptr, "ast_Ast_as_lookaround: a");
    n00b_require(a->tag == AST_TAG_LOOKAROUND,
                 "ast_Ast_as_lookaround: tag mismatch");
    return &a->u.lookaround;
}
const ast_Repetition *ast_Ast_as_repetition(const ast_Ast *a) {
    n00b_require(a != nullptr, "ast_Ast_as_repetition: a");
    n00b_require(a->tag == AST_TAG_REPETITION,
                 "ast_Ast_as_repetition: tag mismatch");
    return &a->u.repetition;
}
const ast_SetFlags *ast_Ast_as_flags(const ast_Ast *a) {
    n00b_require(a != nullptr, "ast_Ast_as_flags: a");
    n00b_require(a->tag == AST_TAG_FLAGS, "ast_Ast_as_flags: tag mismatch");
    return &a->u.flags;
}
const ast_Assertion *ast_Ast_as_assertion(const ast_Ast *a) {
    n00b_require(a != nullptr, "ast_Ast_as_assertion: a");
    n00b_require(a->tag == AST_TAG_ASSERTION,
                 "ast_Ast_as_assertion: tag mismatch");
    return &a->u.assertion;
}

// ---------------------------------------------------------------------------
// ast_Concat
// ---------------------------------------------------------------------------

ast_Concat ast_Concat_new(rs_Span span) {
    return (ast_Concat){ .span = span };
}

size_t ast_Concat_count(const ast_Concat *c) {
    n00b_require(c != nullptr, "ast_Concat_count: c");
    return c->len;
}

const ast_Ast *ast_Concat_get(const ast_Concat *c, size_t i) {
    n00b_require(c != nullptr, "ast_Concat_get: c");
    n00b_require(i < c->len, "ast_Concat_get: index out of range");
    n00b_require(c->len == 0 || c->asts != nullptr,
                 "ast_Concat_get: invariant violated");
    return c->asts[i];
}

void ast_Concat_push_ast(ast_Concat *c, ast_Ast *a, n00b_allocator_t *allocator) {
    n00b_require(c != nullptr, "ast_Concat_push_ast: c");
    n00b_require(a != nullptr, "ast_Concat_push_ast: a");
    if (c->len == c->cap) {
        ast_ptrvec_grow(&c->asts, &c->cap, c->len + 1, allocator);
    }
    c->asts[c->len++] = a;
}

ast_Ast *ast_Concat_pop_ast(ast_Concat *c) {
    n00b_require(c != nullptr, "ast_Concat_pop_ast: c");
    if (c->len == 0) return nullptr;
    ast_Ast *a = c->asts[--c->len];
    c->asts[c->len] = nullptr;
    return a;
}

void ast_Concat_set_span_end(ast_Concat *c, rs_Position end) {
    n00b_require(c != nullptr, "ast_Concat_set_span_end: c");
    c->span.end = end;
}

rs_Position ast_Concat_span_start(const ast_Concat *c) {
    n00b_require(c != nullptr, "ast_Concat_span_start: c");
    return c->span.start;
}

rs_Position ast_Concat_span_end(const ast_Concat *c) {
    n00b_require(c != nullptr, "ast_Concat_span_end: c");
    return c->span.end;
}

ast_Ast *ast_Concat_into_ast_owned(ast_Concat c, n00b_allocator_t *allocator) {
    // 0 -> empty, 1 -> only child, else concat.
    if (c.len == 0) {
        n00b_free(c.asts);
        return ast_Ast_empty_owned(c.span, allocator);
    }
    if (c.len == 1) {
        ast_Ast *only = c.asts[0];
        n00b_free(c.asts);
        return only;
    }
    return ast_Ast_concat_owned(c, allocator);
}

static void ast_concat_drop(ast_Concat *c) {
    if (!c) return;
    for (size_t i = 0; i < c->len; ++i) ast_Ast_free(c->asts[i]);
    n00b_free(c->asts);
    c->asts = nullptr;
    c->len  = 0;
    c->cap  = 0;
}

// ---------------------------------------------------------------------------
// ast_Alternation
// ---------------------------------------------------------------------------

ast_Alternation ast_Alternation_new(rs_Span span) {
    return (ast_Alternation){ .span = span };
}

size_t ast_Alternation_count(const ast_Alternation *a) {
    n00b_require(a != nullptr, "ast_Alternation_count: a");
    return a->len;
}

const ast_Ast *ast_Alternation_get(const ast_Alternation *a, size_t i) {
    n00b_require(a != nullptr, "ast_Alternation_get: a");
    n00b_require(i < a->len, "ast_Alternation_get: index out of range");
    n00b_require(a->len == 0 || a->asts != nullptr,
                 "ast_Alternation_get: invariant violated");
    return a->asts[i];
}

void ast_Alternation_push_ast(ast_Alternation *a, ast_Ast *e,
                              n00b_allocator_t *allocator) {
    n00b_require(a != nullptr, "ast_Alternation_push_ast: a");
    n00b_require(e != nullptr, "ast_Alternation_push_ast: e");
    if (a->len == a->cap) {
        ast_ptrvec_grow(&a->asts, &a->cap, a->len + 1, allocator);
    }
    a->asts[a->len++] = e;
}

void ast_Alternation_set_span_end(ast_Alternation *a, rs_Position end) {
    n00b_require(a != nullptr, "ast_Alternation_set_span_end: a");
    a->span.end = end;
}

rs_Span ast_Alternation_span(const ast_Alternation *a) {
    n00b_require(a != nullptr, "ast_Alternation_span: a");
    return a->span;
}

ast_Ast *ast_Alternation_into_ast_owned(ast_Alternation a,
                                          n00b_allocator_t *allocator) {
    if (a.len == 0) {
        n00b_free(a.asts);
        return ast_Ast_empty_owned(a.span, allocator);
    }
    if (a.len == 1) {
        ast_Ast *only = a.asts[0];
        n00b_free(a.asts);
        return only;
    }
    return ast_Ast_alternation_owned(a, allocator);
}

static void ast_alternation_drop(ast_Alternation *a) {
    if (!a) return;
    for (size_t i = 0; i < a->len; ++i) ast_Ast_free(a->asts[i]);
    n00b_free(a->asts);
    a->asts = nullptr;
    a->len  = 0;
    a->cap  = 0;
}

// ---------------------------------------------------------------------------
// ast_Intersection
// ---------------------------------------------------------------------------

ast_Intersection ast_Intersection_new(rs_Span span) {
    return (ast_Intersection){ .span = span };
}

size_t ast_Intersection_count(const ast_Intersection *i) {
    n00b_require(i != nullptr, "ast_Intersection_count: i");
    return i->len;
}

const ast_Ast *ast_Intersection_get(const ast_Intersection *i, size_t k) {
    n00b_require(i != nullptr, "ast_Intersection_get: i");
    n00b_require(k < i->len, "ast_Intersection_get: index out of range");
    n00b_require(i->len == 0 || i->asts != nullptr,
                 "ast_Intersection_get: invariant violated");
    return i->asts[k];
}

void ast_Intersection_push_ast(ast_Intersection *i, ast_Ast *e,
                                n00b_allocator_t *allocator) {
    n00b_require(i != nullptr, "ast_Intersection_push_ast: i");
    n00b_require(e != nullptr, "ast_Intersection_push_ast: e");
    if (i->len == i->cap) {
        ast_ptrvec_grow(&i->asts, &i->cap, i->len + 1, allocator);
    }
    i->asts[i->len++] = e;
}

void ast_Intersection_set_span_end(ast_Intersection *i, rs_Position end) {
    n00b_require(i != nullptr, "ast_Intersection_set_span_end: i");
    i->span.end = end;
}

rs_Span ast_Intersection_span(const ast_Intersection *i) {
    n00b_require(i != nullptr, "ast_Intersection_span: i");
    return i->span;
}

ast_Ast *ast_Intersection_into_ast_owned(ast_Intersection i,
                                          n00b_allocator_t *allocator) {
    if (i.len == 0) {
        n00b_free(i.asts);
        return ast_Ast_empty_owned(i.span, allocator);
    }
    if (i.len == 1) {
        ast_Ast *only = i.asts[0];
        n00b_free(i.asts);
        return only;
    }
    return ast_Ast_intersection_owned(i, allocator);
}

static void ast_intersection_drop(ast_Intersection *i) {
    if (!i) return;
    for (size_t k = 0; k < i->len; ++k) ast_Ast_free(i->asts[k]);
    n00b_free(i->asts);
    i->asts = nullptr;
    i->len  = 0;
    i->cap  = 0;
}

// ---------------------------------------------------------------------------
// ast_Complement
// ---------------------------------------------------------------------------

ast_Complement ast_Complement_new(rs_Span span, ast_Ast *body) {
    n00b_require(body != nullptr, "ast_Complement_new: body");
    return (ast_Complement){ .span = span, .ast = body };
}

const ast_Ast *ast_Complement_inner(const ast_Complement *c) {
    n00b_require(c != nullptr, "ast_Complement_inner: c");
    return c->ast;
}

static void ast_complement_drop(ast_Complement *c) {
    if (!c) return;
    ast_Ast_free(c->ast);
    c->ast = nullptr;
}

// ---------------------------------------------------------------------------
// ast_Lookaround
// ---------------------------------------------------------------------------

const ast_Ast *ast_Lookaround_inner(const ast_Lookaround *l) {
    n00b_require(l != nullptr, "ast_Lookaround_inner: l");
    return l->ast;
}

ast_LookaroundKind ast_Lookaround_kind(const ast_Lookaround *l) {
    n00b_require(l != nullptr, "ast_Lookaround_kind: l");
    return l->kind;
}

rs_Span ast_Lookaround_span(const ast_Lookaround *l) {
    n00b_require(l != nullptr, "ast_Lookaround_span: l");
    return l->span;
}

static void ast_lookaround_drop(ast_Lookaround *l) {
    if (!l) return;
    ast_Ast_free(l->ast);
    l->ast = nullptr;
}

// ---------------------------------------------------------------------------
// ast_Group
// ---------------------------------------------------------------------------

ast_Group ast_Group_new_capture_index(rs_Span open_span, uint32_t idx,
                                      rs_Span inner_span) {
    (void)inner_span; // the inner span is recorded once Group_set_ast lands
    return (ast_Group){
        .span          = open_span,
        .kind_tag      = AST_GROUP_KIND_CAPTURE_INDEX,
        .capture_index = idx,
    };
}

ast_Group ast_Group_new_capture_name(rs_Span open_span, bool starts_with_p,
                                     ast_CaptureName name, rs_Span inner_span) {
    (void)inner_span;
    // WHY: the CaptureName carries a heap-owned string (transferred in).
    // Stash it on the heap so the 128B Group header isn't blown.
    ast_GroupCaptureName *p = n00b_alloc(ast_GroupCaptureName);
    p->index         = name.index;
    p->starts_with_p = (uint8_t)(starts_with_p ? 1 : 0);
    p->name_span     = name.span;
    p->name          = name.name;
    p->name_len      = name.name_len;
    p->name_cap      = name.name_cap;
    return (ast_Group){
        .span     = open_span,
        .kind_tag = AST_GROUP_KIND_CAPTURE_NAME,
        .payload  = p,
    };
}

ast_Group ast_Group_new_non_capturing(rs_Span open_span, ast_Flags flags,
                                      rs_Span inner_span) {
    (void)inner_span;
    ast_GroupNonCapturing *p = n00b_alloc(ast_GroupNonCapturing);
    p->span  = flags.span;
    p->items = flags.items;
    p->len   = flags.len;
    p->cap   = flags.cap;
    return (ast_Group){
        .span     = open_span,
        .kind_tag = AST_GROUP_KIND_NON_CAPTURING,
        .payload  = p,
    };
}

ast_Group ast_Group_new_lookaround(rs_Span open_span, ast_LookaroundKind kind,
                                   rs_Span inner_span) {
    (void)inner_span;
    return (ast_Group){
        .span            = open_span,
        .kind_tag        = AST_GROUP_KIND_LOOKAROUND,
        .lookaround_kind = kind,
    };
}

ast_Group ast_Group_new_complement(rs_Span open_span, rs_Span inner_span) {
    (void)inner_span;
    return (ast_Group){
        .span     = open_span,
        .kind_tag = AST_GROUP_KIND_COMPLEMENT,
    };
}

const ast_Ast *ast_Group_inner(const ast_Group *g) {
    n00b_require(g != nullptr, "ast_Group_inner: g");
    return g->ast;
}

bool ast_Group_kind_is_complement(const ast_Group *g) {
    n00b_require(g != nullptr, "ast_Group_kind_is_complement: g");
    return g->kind_tag == AST_GROUP_KIND_COMPLEMENT;
}

bool ast_Group_kind_is_non_capturing(const ast_Group *g) {
    n00b_require(g != nullptr, "ast_Group_kind_is_non_capturing: g");
    return g->kind_tag == AST_GROUP_KIND_NON_CAPTURING;
}

const ast_Flags *ast_Group_kind_non_capturing_flags(const ast_Group *g) {
    n00b_require(g != nullptr, "ast_Group_kind_non_capturing_flags: g");
    n00b_require(g->kind_tag == AST_GROUP_KIND_NON_CAPTURING,
                 "ast_Group_kind_non_capturing_flags: tag mismatch");
    // WHY: parser.c reads a `const ast_Flags *`.  Build a stable view by
    // reinterpreting the GroupNonCapturing payload as ast_Flags (compatible
    // prefix: span, items, len, cap — both structs start with rs_Span span
    // followed by the same item-vec triple).
    ast_GroupNonCapturing *p = (ast_GroupNonCapturing *)g->payload;
    n00b_require(p != nullptr, "ast_Group_kind_non_capturing_flags: payload");
    return (const ast_Flags *)p;
}

const ast_Flags *ast_Group_flags(const ast_Group *g) {
    n00b_require(g != nullptr, "ast_Group_flags: g");
    if (g->kind_tag != AST_GROUP_KIND_NON_CAPTURING) return nullptr;
    return ast_Group_kind_non_capturing_flags(g);
}

void ast_Group_set_span_end(ast_Group *g, rs_Position end) {
    n00b_require(g != nullptr, "ast_Group_set_span_end: g");
    g->span.end = end;
}

void ast_Group_set_ast(ast_Group *g, ast_Ast *a) {
    n00b_require(g != nullptr, "ast_Group_set_ast: g");
    if (g->ast) ast_Ast_free(g->ast);
    g->ast = a;
}

ast_Ast *ast_Group_take_ast(ast_Group *g) {
    n00b_require(g != nullptr, "ast_Group_take_ast: g");
    ast_Ast *a = g->ast;
    g->ast = nullptr;
    return a;
}

rs_Span ast_Group_span(const ast_Group *g) {
    n00b_require(g != nullptr, "ast_Group_span: g");
    return g->span;
}

static void ast_group_drop(ast_Group *g) {
    if (!g) return;
    if (g->ast) { ast_Ast_free(g->ast); g->ast = nullptr; }
    if (g->payload) {
        if (g->kind_tag == AST_GROUP_KIND_CAPTURE_NAME) {
            ast_GroupCaptureName *p = (ast_GroupCaptureName *)g->payload;
            n00b_free(p->name);
            n00b_free(p);
        } else if (g->kind_tag == AST_GROUP_KIND_NON_CAPTURING) {
            ast_GroupNonCapturing *p = (ast_GroupNonCapturing *)g->payload;
            n00b_free(p->items);
            n00b_free(p);
        } else {
            n00b_free(g->payload);
        }
        g->payload = nullptr;
    }
}

// ---------------------------------------------------------------------------
// ast_Repetition
// ---------------------------------------------------------------------------

ast_Repetition ast_Repetition_make(rs_Span span,
                                   rs_Span op_span,
                                   ast_RepetitionKind_tag kind,
                                   uint32_t lo, uint32_t hi,
                                   ast_RepetitionRange_tag range,
                                   ast_Ast *body) {
    n00b_require(body != nullptr, "ast_Repetition_make: body");
    return (ast_Repetition){
        .span    = span,
        .op_span = op_span,
        .kind    = kind,
        .range   = range,
        .lo      = lo,
        .hi      = hi,
        .ast     = body,
        .greedy  = 1,
    };
}

const ast_Ast *ast_Repetition_inner(const ast_Repetition *r) {
    n00b_require(r != nullptr, "ast_Repetition_inner: r");
    return r->ast;
}

ast_RepetitionKind_tag ast_Repetition_op_kind_tag(const ast_Repetition *r) {
    n00b_require(r != nullptr, "ast_Repetition_op_kind_tag: r");
    return r->kind;
}

ast_RepetitionRange_tag ast_Repetition_op_range_tag(const ast_Repetition *r) {
    n00b_require(r != nullptr, "ast_Repetition_op_range_tag: r");
    n00b_require(r->kind == AST_REPETITION_RANGE,
                 "ast_Repetition_op_range_tag: not a range");
    return r->range;
}

void ast_Repetition_op_range_bounds(const ast_Repetition *r,
                                    uint32_t *lo, uint32_t *hi) {
    n00b_require(r != nullptr, "ast_Repetition_op_range_bounds: r");
    if (lo) *lo = r->lo;
    if (hi) *hi = r->hi;
}

static void ast_repetition_drop(ast_Repetition *r) {
    if (!r) return;
    if (r->ast) { ast_Ast_free(r->ast); r->ast = nullptr; }
}

// ---------------------------------------------------------------------------
// ast_Assertion
// ---------------------------------------------------------------------------

ast_AssertionKind ast_Assertion_kind(const ast_Assertion *a) {
    n00b_require(a != nullptr, "ast_Assertion_kind: a");
    return (ast_AssertionKind)a->kind;
}

rs_Span ast_Assertion_span_get(const ast_Assertion *a) {
    n00b_require(a != nullptr, "ast_Assertion_span_get: a");
    return a->span;
}

// ---------------------------------------------------------------------------
// ast_CaptureName
// ---------------------------------------------------------------------------

ast_CaptureName ast_CaptureName_make(rs_Span span, char *name_owned, uint32_t index) {
    n00b_require(name_owned != nullptr, "ast_CaptureName_make: name_owned");
    size_t nlen = cstr_len(name_owned);
    return (ast_CaptureName){
        .span     = span,
        .name     = name_owned,
        .name_len = nlen,
        .name_cap = nlen + 1,
        .index    = index,
    };
}

const char *ast_CaptureName_name(const ast_CaptureName *c) {
    n00b_require(c != nullptr, "ast_CaptureName_name: c");
    return c->name;
}

rs_Span ast_CaptureName_span(const ast_CaptureName *c) {
    n00b_require(c != nullptr, "ast_CaptureName_span: c");
    return c->span;
}

// ---------------------------------------------------------------------------
// ast_ClassPerl / ast_ClassUnicode / ast_Literal — concrete rs_* accessors.
// ---------------------------------------------------------------------------

uint32_t ast_Literal_char(const rs_Literal *l) {
    n00b_require(l != nullptr, "ast_Literal_char: l");
    return l->c;
}

bool ast_ClassPerl_negated(const rs_ClassPerl *c) {
    n00b_require(c != nullptr, "ast_ClassPerl_negated: c");
    return c->negated;
}

rs_ClassPerlKind ast_ClassPerl_kind(const rs_ClassPerl *c) {
    n00b_require(c != nullptr, "ast_ClassPerl_kind: c");
    return c->kind;
}

bool ast_ClassUnicode_negated(const rs_ClassUnicode *c) {
    n00b_require(c != nullptr, "ast_ClassUnicode_negated: c");
    return c->negated;
}

// ---------------------------------------------------------------------------
// ast_Comment
// ---------------------------------------------------------------------------

void ast_Comment_set_text(ast_Comment *c, char *text) {
    n00b_require(c != nullptr, "ast_Comment_set_text: c");
    // `text` may legitimately be nullptr for an empty comment; allow it.
    if (c->comment) n00b_free(c->comment);
    c->comment = text;
}

// ---------------------------------------------------------------------------
// ast_Flags / ast_FlagsItem / ast_SetFlags
// ---------------------------------------------------------------------------

ast_Flags ast_Flags_new(rs_Span span) {
    return (ast_Flags){ .span = span };
}

int ast_Flags_add_item(ast_Flags *f, ast_FlagsItem item,
                        n00b_allocator_t *allocator) {
    n00b_require(f != nullptr, "ast_Flags_add_item: f");
    n00b_require(f->len == 0 || f->items != nullptr,
                 "ast_Flags_add_item: invariant violated");
    // Returns Some(i) on dupe, None on insert.  In C: returns the duplicate
    // index (>=0) or -1 on insert.
    for (size_t i = 0; i < f->len; ++i) {
        const ast_FlagsItem *x = &f->items[i];
        bool same;
        if (x->is_negation && item.is_negation) {
            same = true;
        } else if (!x->is_negation && !item.is_negation) {
            same = (x->flag == item.flag);
        } else {
            same = false;
        }
        if (same) return (int)i;
    }
    if (f->len == f->cap) {
        ast_flagsitem_grow(&f->items, &f->cap, f->len + 1, allocator);
    }
    f->items[f->len++] = item;
    return -1;
}

int ast_Flags_flag_state(const ast_Flags *f, ast_Flag flag) {
    n00b_require(f != nullptr, "ast_Flags_flag_state: f");
    n00b_require(f->len == 0 || f->items != nullptr,
                 "ast_Flags_flag_state: invariant violated");
    // Returns: -1 = absent (Rust None), 0 = present-and-negated,
    //           1 = present-and-set.
    bool negated = false;
    for (size_t i = 0; i < f->len; ++i) {
        const ast_FlagsItem *x = &f->items[i];
        if (x->is_negation) {
            negated = true;
        } else if (x->flag == flag) {
            return negated ? 0 : 1;
        }
    }
    return -1;
}

ast_FlagsItem ast_Flags_get_item(const ast_Flags *f, size_t i) {
    n00b_require(f != nullptr, "ast_Flags_get_item: f");
    n00b_require(i < f->len, "ast_Flags_get_item: index out of range");
    n00b_require(f->items != nullptr, "ast_Flags_get_item: items is null");
    return f->items[i];
}

bool ast_Flags_is_empty(const ast_Flags *f) {
    n00b_require(f != nullptr, "ast_Flags_is_empty: f");
    return f->len == 0;
}

bool ast_Flags_items_empty(const ast_Flags *f) {
    n00b_require(f != nullptr, "ast_Flags_items_empty: f");
    return f->len == 0;
}

void ast_Flags_set_span_end(ast_Flags *f, rs_Position end) {
    n00b_require(f != nullptr, "ast_Flags_set_span_end: f");
    f->span.end = end;
}

ast_FlagsItem ast_FlagsItem_negation(rs_Span span) {
    return (ast_FlagsItem){ .span = span, .is_negation = 1 };
}

ast_FlagsItem ast_FlagsItem_flag(rs_Span span, ast_Flag flag) {
    return (ast_FlagsItem){ .span = span, .is_negation = 0, .flag = flag };
}

rs_Span ast_FlagsItem_span(const ast_FlagsItem *fi) {
    n00b_require(fi != nullptr, "ast_FlagsItem_span: fi");
    return fi->span;
}

ast_SetFlags ast_SetFlags_make(rs_Span span, ast_Flags flags) {
    return (ast_SetFlags){
        .span       = span,
        .items      = flags.items,
        .items_len  = flags.len,
        .items_cap  = flags.cap,
        .flags_span = flags.span,
    };
}

int ast_SetFlags_flag_state(const ast_SetFlags *f, ast_Flag flag) {
    n00b_require(f != nullptr, "ast_SetFlags_flag_state: f");
    // Reconstruct a transient ast_Flags view to delegate.
    ast_Flags view = (ast_Flags){
        .span  = f->flags_span,
        .items = f->items,
        .len   = f->items_len,
        .cap   = f->items_cap,
    };
    return ast_Flags_flag_state(&view, flag);
}

rs_Span ast_SetFlags_span(const ast_SetFlags *f) {
    n00b_require(f != nullptr, "ast_SetFlags_span: f");
    return f->span;
}

static void ast_flags_drop(ast_Flags *f) {
    if (!f) return;
    n00b_free(f->items);
    f->items = nullptr;
    f->len   = 0;
    f->cap   = 0;
}

static void ast_setflags_drop(ast_SetFlags *f) {
    if (!f) return;
    n00b_free(f->items);
    f->items     = nullptr;
    f->items_len = 0;
    f->items_cap = 0;
}

// ===========================================================================
// Small accessor stubs for the externally-opaque rs_* types used by the
// original `Ast` surface (Span / Literal / ClassPerl / ClassUnicode /
// ClassBracketed).  These wrappers return null pointers / zero values so
// callers link cleanly while the cross-file regex_syntax port is in
// progress; the active path through the parser uses the rs_* / ast_*
// concrete-layout API above.
// ===========================================================================

const Span *class_bracketed_span(const ClassBracketed *c) { (void)c; return nullptr; }
const Span *class_perl_span     (const ClassPerl *c)      { (void)c; return nullptr; }
const Span *class_unicode_span  (const ClassUnicode *c)   { (void)c; return nullptr; }
const Span *literal_span        (const Literal *l)        { (void)l; return nullptr; }
Span       *span_clone          (const Span *s)           { (void)s; return nullptr; }

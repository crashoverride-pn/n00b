/**
 * @file ast.h
 * @brief Regex AST type definitions, mirroring the upstream Rust
 *        `regex_syntax::ast` crate.
 *
 * Two surfaces co-exist here:
 *
 * 1. The original `Ast` / `Span` / `Literal` / `ClassUnicode` / `ClassPerl` /
 *    `ClassBracketed` / `Group` / `Flags` family of types and constructors.
 *    External Rust newtypes (`Span`, `Literal`, `ClassUnicode`, `ClassPerl`,
 *    `ClassBracketed`) are forward-declared as opaque structs.
 *
 * 2. The namespaced `ast_*` / `rs_*` API used by `parser.c` and
 *    `regex_syntax.c`.  The `rs_*` types are concrete POD layouts that mirror
 *    the upstream Rust newtypes byte-for-byte; the `ast_*` types are the
 *    parser's view of the AST.
 *
 * The names stay un-prefixed (no `n00b_`) because they form the regex
 * algorithmic vocabulary tracked against upstream Rust; the header lives
 * under `include/internal/regex/` and is not part of the public n00b
 * surface.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/alloc.h"  // n00b_allocator_t — required for ast constructors.
#include "adt/variant.h"  // n00b_variant_t — GroupKind tagged union.

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Forward declarations of types defined outside this file.
// These come from the `regex_syntax::ast` crate in the original Rust.
// ---------------------------------------------------------------------------

typedef struct Span           Span;
typedef struct Literal        Literal;
typedef struct ClassUnicode   ClassUnicode;
typedef struct ClassPerl      ClassPerl;
typedef struct ClassBracketed ClassBracketed;

// ---------------------------------------------------------------------------
// Simple owning string / vector types used in this translation.
// NOTE: Rust `String` and `Vec<T>` are mapped to length+pointer structs.
// The original code relies on Rust ownership; in C, callers are
// responsible for lifetime management.
// ---------------------------------------------------------------------------

typedef struct {
    char  *data;     // NUL-terminated, owning
    size_t len;
    size_t cap;
} ResharpString;

// Forward declarations of AST types so we can use pointers below.
typedef struct Ast              Ast;
typedef struct WithComments     WithComments;
typedef struct Comment          Comment;
typedef struct Alternation      Alternation;
typedef struct Concat           Concat;
typedef struct Assertion        Assertion;
typedef struct Repetition       Repetition;
typedef struct RepetitionOp     RepetitionOp;
typedef struct RepetitionRange  RepetitionRange;
typedef struct Group            Group;
// GroupKind is a n00b_variant_t (defined below, after CaptureName), so no
// forward `typedef struct GroupKind GroupKind;` here — the variant typedef
// supplies the name and a `struct GroupKind` predeclaration would clash.
typedef struct CaptureName      CaptureName;
typedef struct SetFlags         SetFlags;
typedef struct Flags            Flags;
typedef struct FlagsItem        FlagsItem;
typedef struct FlagsItemKind    FlagsItemKind;
typedef struct Intersection     Intersection;
typedef struct Complement       Complement;
typedef struct Lookaround       Lookaround;
typedef struct Error            Error;
typedef struct ErrorKind        ErrorKind;

// Vec<Ast>
typedef struct {
    Ast    *data;
    size_t  len;
    size_t  cap;
} AstVec;

// Vec<Comment>
typedef struct {
    Comment *data;
    size_t   len;
    size_t   cap;
} CommentVec;

// Vec<FlagsItem>
typedef struct {
    FlagsItem *data;
    size_t     len;
    size_t     cap;
} FlagsItemVec;

// ---------------------------------------------------------------------------
// ErrorKind
// ---------------------------------------------------------------------------

typedef enum : int {
    ERROR_KIND_CAPTURE_LIMIT_EXCEEDED,
    ERROR_KIND_CLASS_ESCAPE_INVALID,
    ERROR_KIND_CLASS_RANGE_INVALID,
    ERROR_KIND_CLASS_RANGE_LITERAL,
    ERROR_KIND_CLASS_UNCLOSED,
    ERROR_KIND_DECIMAL_EMPTY,
    ERROR_KIND_DECIMAL_INVALID,
    ERROR_KIND_ESCAPE_HEX_EMPTY,
    ERROR_KIND_ESCAPE_HEX_INVALID,
    ERROR_KIND_ESCAPE_HEX_INVALID_DIGIT,
    ERROR_KIND_ESCAPE_UNEXPECTED_EOF,
    ERROR_KIND_ESCAPE_UNRECOGNIZED,
    ERROR_KIND_FLAG_DANGLING_NEGATION,
    ERROR_KIND_FLAG_DUPLICATE,           // carries Span original
    ERROR_KIND_FLAG_REPEATED_NEGATION,   // carries Span original
    ERROR_KIND_FLAG_UNEXPECTED_EOF,
    ERROR_KIND_FLAG_UNRECOGNIZED,
    ERROR_KIND_GROUP_NAME_DUPLICATE,     // carries Span original
    ERROR_KIND_GROUP_NAME_EMPTY,
    ERROR_KIND_GROUP_NAME_INVALID,
    ERROR_KIND_GROUP_NAME_UNEXPECTED_EOF,
    ERROR_KIND_GROUP_UNCLOSED,
    ERROR_KIND_GROUP_UNOPENED,
    ERROR_KIND_NEST_LIMIT_EXCEEDED,      // carries u32 limit
    ERROR_KIND_REPETITION_COUNT_INVALID,
    ERROR_KIND_REPETITION_COUNT_DECIMAL_EMPTY,
    ERROR_KIND_REPETITION_COUNT_UNCLOSED,
    ERROR_KIND_REPETITION_MISSING,
    ERROR_KIND_SPECIAL_WORD_BOUNDARY_UNCLOSED,
    ERROR_KIND_SPECIAL_WORD_BOUNDARY_UNRECOGNIZED,
    ERROR_KIND_SPECIAL_WORD_OR_REPETITION_UNEXPECTED_EOF,
    ERROR_KIND_UNICODE_CLASS_INVALID,
    ERROR_KIND_UNSUPPORTED_BACKREFERENCE,
    ERROR_KIND_UNSUPPORTED_LOOK_AROUND,
    ERROR_KIND_UNSUPPORTED_RESHARP_REGEX,
    ERROR_KIND_UNSUPPORTED_LAZY_QUANTIFIER,
    ERROR_KIND_COMPLEMENT_GROUP_EXPECTED,
} ErrorKindTag;

struct ErrorKind {
    ErrorKindTag tag;
    union [[n00b::raw_union]] {
        Span    *flag_duplicate_original;         // FlagDuplicate
        Span    *flag_repeated_negation_original; // FlagRepeatedNegation
        Span    *group_name_duplicate_original;   // GroupNameDuplicate
        uint32_t nest_limit_exceeded;             // NestLimitExceeded(u32)
    } u;
};

struct Error {
    ErrorKind     kind;
    ResharpString pattern;
    Span         *span;
};

// Accessors mirroring the Rust impl.
const ErrorKind *error_kind(const Error *self);
const char      *error_pattern(const Error *self);
const Span      *error_span(const Error *self);
// Returns nullptr if no auxiliary span is available.
const Span      *error_auxiliary_span(const Error *self);

// `core::fmt::Display` -> writes a human-readable message to buf.
// Returns the number of bytes written (excluding terminating nul), or a
// negative value on error.
int error_kind_display(const ErrorKind *self, char *buf, size_t buflen);

// ---------------------------------------------------------------------------
// Ast
// ---------------------------------------------------------------------------

typedef enum : int {
    AST_EMPTY,
    AST_FLAGS,
    AST_LITERAL,
    AST_DOT,
    AST_TOP,
    AST_ASSERTION,
    AST_CLASS_UNICODE,
    AST_CLASS_PERL,
    AST_CLASS_BRACKETED,
    AST_REPETITION,
    AST_GROUP,
    AST_ALTERNATION,
    AST_CONCAT,
    AST_INTERSECTION,
    AST_COMPLEMENT,
    AST_LOOKAROUND,
} AstTag;

// NOTE: Rust uses `Box<T>` for each variant.  We mirror that with owning
// pointers.  Cross-file ownership/lifetimes are out of scope for this
// file-by-file phase.
struct Ast {
    AstTag tag;
    union [[n00b::raw_union]] {
        Span           *empty;           // AST_EMPTY
        SetFlags       *flags;           // AST_FLAGS
        Literal        *literal;         // AST_LITERAL
        Span           *dot;             // AST_DOT
        Span           *top;             // AST_TOP
        Assertion      *assertion;       // AST_ASSERTION
        ClassUnicode   *class_unicode;   // AST_CLASS_UNICODE
        ClassPerl     *class_perl;       // AST_CLASS_PERL
        ClassBracketed *class_bracketed; // AST_CLASS_BRACKETED
        Repetition     *repetition;      // AST_REPETITION
        Group          *group;           // AST_GROUP
        Alternation    *alternation;     // AST_ALTERNATION
        Concat         *concat;          // AST_CONCAT
        Intersection   *intersection;    // AST_INTERSECTION
        Complement     *complement;      // AST_COMPLEMENT
        Lookaround     *lookaround;      // AST_LOOKAROUND
    } u;
};

// Constructors: each one consumes/owns the argument as in Rust's `Box::new`.
Ast ast_empty(Span *span);
Ast ast_flags(SetFlags *e);
Ast ast_literal(Literal *e);
Ast ast_dot(Span *span);
Ast ast_top(Span *span);
Ast ast_assertion(Assertion *e);
Ast ast_class_unicode(ClassUnicode *e);
Ast ast_class_perl(ClassPerl *e);
Ast ast_class_bracketed(ClassBracketed *e);
Ast ast_repetition(Repetition *e);
// Group constructor dispatches based on kind, mirroring `Ast::group`.
Ast ast_group(Group *e);
Ast ast_alternation(Alternation *e);
Ast ast_concat(Concat *e);
Ast ast_intersection(Intersection *e);
Ast ast_complement(Complement *e);
Ast ast_lookaround(Lookaround *e);

// Return the span of this AST.  Borrowed pointer; do not free.
const Span *ast_span(const Ast *self);
bool        ast_is_empty(const Ast *self);
// Internal in Rust; exposed here for parity with the file.
bool        ast_has_subexprs(const Ast *self);

// ---------------------------------------------------------------------------
// WithComments / Comment
// ---------------------------------------------------------------------------

struct WithComments {
    Ast        ast;
    CommentVec comments;
};

struct Comment {
    Span         *span;
    ResharpString comment;
};

// ---------------------------------------------------------------------------
// Alternation / Concat
// ---------------------------------------------------------------------------

struct Alternation {
    Span  *span;
    AstVec asts;
};

// Consumes `self`.  If 0 ASTs -> empty; 1 -> the AST; otherwise alternation.
Ast alternation_into_ast(Alternation *self);

struct Concat {
    Span  *span;
    AstVec asts;
};

Ast concat_into_ast(Concat *self);

// ---------------------------------------------------------------------------
// Assertion
// ---------------------------------------------------------------------------

typedef enum : int {
    ASSERTION_START_LINE,
    ASSERTION_END_LINE,
    ASSERTION_START_TEXT,
    ASSERTION_END_TEXT,
    ASSERTION_WORD_BOUNDARY,
    ASSERTION_NOT_WORD_BOUNDARY,
    ASSERTION_WORD_BOUNDARY_START,
    ASSERTION_WORD_BOUNDARY_END,
    ASSERTION_WORD_BOUNDARY_START_ANGLE,
    ASSERTION_WORD_BOUNDARY_END_ANGLE,
    ASSERTION_WORD_BOUNDARY_START_HALF,
    ASSERTION_WORD_BOUNDARY_END_HALF,
} AssertionKind;

struct Assertion {
    Span         *span;
    AssertionKind kind;
};

// ---------------------------------------------------------------------------
// Repetition
// ---------------------------------------------------------------------------

typedef enum : int {
    REPETITION_RANGE_EXACTLY,  // u32 m
    REPETITION_RANGE_AT_LEAST, // u32 m
    REPETITION_RANGE_BOUNDED,  // u32 m, u32 n
} RepetitionRangeTag;

struct RepetitionRange {
    RepetitionRangeTag tag;
    uint32_t           m;
    uint32_t           n; // used only by Bounded
};

bool RepetitionRange_is_valid(const RepetitionRange *self);

typedef enum : int {
    REPETITION_KIND_ZERO_OR_ONE,
    REPETITION_KIND_ZERO_OR_MORE,
    REPETITION_KIND_ONE_OR_MORE,
    REPETITION_KIND_RANGE,
} RepetitionKindTag;

typedef struct RepetitionKind {
    RepetitionKindTag tag;
    RepetitionRange   range; // valid iff tag == REPETITION_KIND_RANGE
} RepetitionKind;

struct RepetitionOp {
    Span          *span;
    RepetitionKind kind;
};

struct Repetition {
    Span        *span;
    RepetitionOp op;
    bool         greedy;
    Ast         *ast;  // Box<Ast>
};

// ---------------------------------------------------------------------------
// Group / GroupKind / CaptureName
// ---------------------------------------------------------------------------

typedef enum : int {
    LOOKAROUND_KIND_POSITIVE_LOOKAHEAD,
    LOOKAROUND_KIND_NEGATIVE_LOOKAHEAD,
    LOOKAROUND_KIND_POSITIVE_LOOKBEHIND,
    LOOKAROUND_KIND_NEGATIVE_LOOKBEHIND,
} LookaroundKind;

struct CaptureName {
    Span         *span;
    ResharpString name;
    uint32_t      index;
};

// CAPTURE_NAME arm payload, hoisted to a named type so it can be a variant arm.
typedef struct GroupKind_capture_name_t {
    bool        starts_with_p;
    CaptureName name;
} GroupKind_capture_name_t;

// GroupKind as a type-safe tagged union.  Arms:
//   uint32_t                  -> capture index (was GROUP_KIND_CAPTURE_INDEX)
//   GroupKind_capture_name_t  -> named capture (was GROUP_KIND_CAPTURE_NAME)
//   Flags *                   -> non-capturing flags (was GROUP_KIND_NON_CAPTURING)
//   LookaroundKind            -> lookaround (was GROUP_KIND_LOOKAROUND)
// The former GROUP_KIND_COMPLEMENT carries no payload and is represented by
// the empty selector (selector == 0).
typedef n00b_variant_t(uint32_t,
                       GroupKind_capture_name_t,
                       Flags *,
                       LookaroundKind) GroupKind;

struct Group {
    Span     *span;
    GroupKind kind;
    Ast      *ast;
};

// Returns nullptr if not non-capturing.  Borrowed pointer.
const Flags *group_flags(const Group *self);
bool         group_is_capturing(const Group *self);
// Returns true and writes to *out if a capture index is available.
bool         group_capture_index(const Group *self, uint32_t *out);

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

typedef enum : int {
    FLAG_CASE_INSENSITIVE,
    FLAG_MULTI_LINE,
    FLAG_DOT_MATCHES_NEW_LINE,
    FLAG_SWAP_GREED,
    FLAG_UNICODE,
    FLAG_CRLF,
    FLAG_IGNORE_WHITESPACE,
} Flag;

typedef enum : int {
    FLAGS_ITEM_KIND_NEGATION,
    FLAGS_ITEM_KIND_FLAG,
} FlagsItemKindTag;

struct FlagsItemKind {
    FlagsItemKindTag tag;
    Flag             flag; // valid iff tag == FLAGS_ITEM_KIND_FLAG
};

bool flags_item_kind_is_negation(const FlagsItemKind *self);

struct FlagsItem {
    Span         *span;
    FlagsItemKind kind;
};

struct Flags {
    Span        *span;
    FlagsItemVec items;
};

struct SetFlags {
    Span *span;
    Flags flags;
};

// Returns true if the item was added; if the item is a duplicate, returns
// false and writes the duplicate index to *out_index.
bool flags_add_item(Flags *self, FlagsItem item, size_t *out_index);

// Three-state flag query.
// Returns:
//   0 -> flag not present (Rust None)
//   1 -> flag present, *out = true if not negated, false if negated
// NOTE: callers must distinguish "absent" from "false"; matches Rust
// `Option<bool>` semantics.
int flags_flag_state(const Flags *self, Flag flag, bool *out);

// ---------------------------------------------------------------------------
// Intersection / Complement / Lookaround
// ---------------------------------------------------------------------------

struct Intersection {
    Span  *span;
    AstVec asts;
};

Ast intersection_into_ast(Intersection *self);

struct Complement {
    Span *span;
    Ast  *ast;
};

Ast complement_into_ast(Complement *self);

struct Lookaround {
    LookaroundKind kind;
    Span          *span;
    Ast           *ast;
};

Ast lookaround_into_ast(Lookaround *self);

// ===========================================================================
// Namespaced ast_<Type>_<method> API used by parser/parser.c.
//
// The translator that produced parser.c chose `ast_<TypeName>_…` PascalCase
// symbol names and uses concrete by-value `rs_Span` / `rs_Position` POD
// types.  This section gives those call sites real prototypes and a
// parallel set of by-value structs that exactly mirror the layouts the
// parser expects.  The 128-byte ABI footprint (with `_pad[]` slots) in
// resharp-c was load-bearing across the lib.h boundary; we preserve it
// here so the two .c TUs compile against a stable shape.
// ===========================================================================

// Concrete POD spans/positions, byte-for-byte compatible with parser.c.
typedef struct rs_Position {
    size_t offset;
    size_t line;
    size_t column;
} rs_Position;

typedef struct rs_Span {
    rs_Position start;
    rs_Position end;
} rs_Span;

// ---------------------------------------------------------------------------
// regex_syntax::ast / hir / utf8 — concrete C layouts.
//
// The faithful subset (Span, Position, Literal, ClassPerl, ClassUnicode,
// ClassBracketed, ClassSet, ClassSetItem, ClassSetUnion, ClassSetRange,
// ClassAscii) mirrors the upstream; recursive variants box their payload
// via heap pointers.  Translator / Hir / Utf8Sequences are stubs whose
// layouts only need to round-trip through parser.c.
// ---------------------------------------------------------------------------

typedef enum {
    RS_CLASS_PERL_KIND_DIGIT,
    RS_CLASS_PERL_KIND_SPACE,
    RS_CLASS_PERL_KIND_WORD,
} rs_ClassPerlKind;

typedef enum {
    RS_CLASS_SET_BINARY_OP_INTERSECTION,
    RS_CLASS_SET_BINARY_OP_DIFFERENCE,
    RS_CLASS_SET_BINARY_OP_SYMMETRIC_DIFFERENCE,
} rs_ClassSetBinaryOpKind;

typedef enum {
    RS_HEX_LITERAL_X,
    RS_HEX_LITERAL_UNICODE_SHORT,
    RS_HEX_LITERAL_UNICODE_LONG,
} rs_HexLiteralKind;

typedef enum {
    RS_SPECIAL_LITERAL_BELL,
    RS_SPECIAL_LITERAL_FORM_FEED,
    RS_SPECIAL_LITERAL_TAB,
    RS_SPECIAL_LITERAL_LINE_FEED,
    RS_SPECIAL_LITERAL_CARRIAGE_RETURN,
    RS_SPECIAL_LITERAL_VERTICAL_TAB,
} rs_SpecialLiteralKind;

typedef enum {
    RS_LITERAL_KIND_VERBATIM,
    RS_LITERAL_KIND_META,
    RS_LITERAL_KIND_SUPERFLUOUS,
    RS_LITERAL_KIND_OCTAL,
    RS_LITERAL_KIND_HEX_FIXED,
    RS_LITERAL_KIND_HEX_BRACE,
    RS_LITERAL_KIND_SPECIAL,
} rs_LiteralKind;

typedef enum {
    RS_CLASS_UNICODE_OP_NOT_EQUAL,
    RS_CLASS_UNICODE_OP_COLON,
    RS_CLASS_UNICODE_OP_EQUAL,
} rs_ClassUnicodeOpKind;

typedef enum {
    RS_CLASS_UNICODE_KIND_ONE_LETTER,
    RS_CLASS_UNICODE_KIND_NAMED,
    RS_CLASS_UNICODE_KIND_NAMED_VALUE,
} rs_ClassUnicodeKindTag;

// Forward declarations for recursive nested types.
typedef struct rs_ClassSet       rs_ClassSet;
typedef struct rs_ClassSetItem   rs_ClassSetItem;
typedef struct rs_ClassSetUnion  rs_ClassSetUnion;
typedef struct rs_ClassSetRange  rs_ClassSetRange;
typedef struct rs_ClassBracketed rs_ClassBracketed;

// rs_Literal — Span + LiteralKind + char.
// The kind variant payload (HexLiteralKind / SpecialLiteralKind) is stored
// inline because it's a small enum.
typedef struct rs_Literal {
    rs_Span               span;
    rs_LiteralKind        kind;
    rs_HexLiteralKind     hex_kind;     // valid iff kind == HEX_FIXED|HEX_BRACE
    rs_SpecialLiteralKind special_kind; // valid iff kind == SPECIAL
    uint32_t              c;            // Unicode scalar value
} rs_Literal;

// rs_ClassPerl — Span + kind + negated.
typedef struct rs_ClassPerl {
    rs_Span          span;
    rs_ClassPerlKind kind;
    bool             negated;
} rs_ClassPerl;

// rs_ClassAscii kind index.
typedef enum {
    RS_CLASS_ASCII_KIND_ALNUM,
    RS_CLASS_ASCII_KIND_ALPHA,
    RS_CLASS_ASCII_KIND_ASCII,
    RS_CLASS_ASCII_KIND_BLANK,
    RS_CLASS_ASCII_KIND_CNTRL,
    RS_CLASS_ASCII_KIND_DIGIT,
    RS_CLASS_ASCII_KIND_GRAPH,
    RS_CLASS_ASCII_KIND_LOWER,
    RS_CLASS_ASCII_KIND_PRINT,
    RS_CLASS_ASCII_KIND_PUNCT,
    RS_CLASS_ASCII_KIND_SPACE,
    RS_CLASS_ASCII_KIND_UPPER,
    RS_CLASS_ASCII_KIND_WORD,
    RS_CLASS_ASCII_KIND_XDIGIT,
} rs_ClassAsciiKind;

typedef struct rs_ClassAscii {
    rs_Span span;
    int     kind;     // rs_ClassAsciiKind, kept as int to match parser.c FFI
    bool    negated;
} rs_ClassAscii;

// rs_ClassUnicode — Span + negated + kind tag + per-kind payload.
// Strings (name / value) are heap-owned NUL-terminated; cloning duplicates.
typedef struct rs_ClassUnicode {
    rs_Span                span;
    bool                   negated;
    rs_ClassUnicodeKindTag kind_tag;
    // OneLetter: c.
    uint32_t               one_letter;
    // Named / NamedValue: heap-owned NUL-terminated name and value.
    char                  *name;
    char                  *value;
    rs_ClassUnicodeOpKind  op;          // valid iff kind_tag == NAMED_VALUE
} rs_ClassUnicode;

// rs_ClassSetUnion — Span + Vec<ClassSetItem>.  Items are heap-owned; the
// vec backing is a contiguous array of rs_ClassSetItem (each of which may
// itself contain further heap pointers).
typedef struct rs_ClassSetUnion {
    rs_Span           span;
    rs_ClassSetItem  *items;   // heap, len * sizeof(rs_ClassSetItem)
    size_t            len;
    size_t            cap;
} rs_ClassSetUnion;

// rs_ClassSetItem — tagged union over the variants from the regex_syntax AST.
typedef enum {
    RS_CLASS_SET_ITEM_EMPTY,
    RS_CLASS_SET_ITEM_LITERAL,
    RS_CLASS_SET_ITEM_RANGE,
    RS_CLASS_SET_ITEM_ASCII,
    RS_CLASS_SET_ITEM_UNICODE,
    RS_CLASS_SET_ITEM_PERL,
    RS_CLASS_SET_ITEM_BRACKETED,
    RS_CLASS_SET_ITEM_UNION,
} rs_ClassSetItemTag;

struct rs_ClassSetItem {
    rs_ClassSetItemTag tag;
    // Empty: just span.
    rs_Span            empty_span;
    rs_Literal         literal;
    rs_ClassSetRange  *range;     // heap (recursive)
    rs_ClassAscii      ascii;
    rs_ClassUnicode    unicode;
    rs_ClassPerl       perl;
    rs_ClassBracketed *bracketed; // heap (recursive)
    rs_ClassSetUnion   union_;    // contains heap items pointer
};

// rs_ClassSetRange — Span + start Literal + end Literal.
struct rs_ClassSetRange {
    rs_Span    span;
    rs_Literal start;
    rs_Literal end;
};

// rs_ClassSet — Item or BinaryOp.  BinaryOp boxes both sides.
typedef enum {
    RS_CLASS_SET_TAG_ITEM,
    RS_CLASS_SET_TAG_BINARY_OP,
} rs_ClassSetTag;

struct rs_ClassSet {
    rs_ClassSetTag           tag;
    // For ITEM:
    rs_ClassSetItem          item;
    // For BINARY_OP:
    rs_Span                  binop_span;
    rs_ClassSetBinaryOpKind  binop_kind;
    rs_ClassSet             *lhs;
    rs_ClassSet             *rhs;
};

// rs_ClassBracketed — Span + negated + kind (ClassSet).
struct rs_ClassBracketed {
    rs_Span     span;
    bool        negated;
    rs_ClassSet kind;
};

// Translator carries flag state; Hir is a sum type built up by
// regex_syntax.c; Utf8Sequences walks a UTF-8 byte-range encoding.
typedef struct rs_TranslatorBuilder {
    bool case_insensitive;
    bool unicode;
    bool utf8;
} rs_TranslatorBuilder;

typedef struct rs_Translator {
    bool case_insensitive;
    bool unicode;
    bool utf8;
} rs_Translator;

typedef struct rs_Hir            rs_Hir;
typedef struct rs_Utf8Sequences  rs_Utf8Sequences;

// ast_ErrorKind — concrete shape used by parser.c's ParseError.  Distinct
// from the existing ErrorKind/ErrorKindTag above (different field layout:
// .tag + flat .original rs_Span, instead of a tagged union).
typedef enum {
    AST_ERROR_KIND_CLASS_ESCAPE_INVALID,
    AST_ERROR_KIND_CLASS_RANGE_LITERAL,
    AST_ERROR_KIND_CLASS_RANGE_INVALID,
    AST_ERROR_KIND_CLASS_UNCLOSED,
    AST_ERROR_KIND_GROUP_UNCLOSED,
    AST_ERROR_KIND_GROUP_UNOPENED,
    AST_ERROR_KIND_GROUP_NAME_INVALID,
    AST_ERROR_KIND_GROUP_NAME_EMPTY,
    AST_ERROR_KIND_GROUP_NAME_DUPLICATE,
    AST_ERROR_KIND_GROUP_NAME_UNEXPECTED_EOF,
    AST_ERROR_KIND_FLAG_REPEATED_NEGATION,
    AST_ERROR_KIND_FLAG_DUPLICATE,
    AST_ERROR_KIND_FLAG_UNRECOGNIZED,
    AST_ERROR_KIND_FLAG_UNEXPECTED_EOF,
    AST_ERROR_KIND_FLAG_DANGLING_NEGATION,
    AST_ERROR_KIND_REPETITION_MISSING,
    AST_ERROR_KIND_REPETITION_COUNT_INVALID,
    AST_ERROR_KIND_REPETITION_COUNT_UNCLOSED,
    AST_ERROR_KIND_REPETITION_COUNT_DECIMAL_EMPTY,
    AST_ERROR_KIND_DECIMAL_EMPTY,
    AST_ERROR_KIND_DECIMAL_INVALID,
    AST_ERROR_KIND_ESCAPE_UNEXPECTED_EOF,
    AST_ERROR_KIND_ESCAPE_HEX_INVALID,
    AST_ERROR_KIND_ESCAPE_HEX_INVALID_DIGIT,
    AST_ERROR_KIND_ESCAPE_HEX_EMPTY,
    AST_ERROR_KIND_ESCAPE_UNRECOGNIZED,
    AST_ERROR_KIND_UNSUPPORTED_BACKREFERENCE,
    AST_ERROR_KIND_UNSUPPORTED_LAZY_QUANTIFIER,
    AST_ERROR_KIND_UNSUPPORTED_RESHARP_REGEX,
    AST_ERROR_KIND_UNICODE_CLASS_INVALID,
    AST_ERROR_KIND_CAPTURE_LIMIT_EXCEEDED,
    AST_ERROR_KIND_COMPLEMENT_GROUP_EXPECTED,
    AST_ERROR_KIND_SPECIAL_WORD_BOUNDARY_UNCLOSED,
    AST_ERROR_KIND_SPECIAL_WORD_BOUNDARY_UNRECOGNIZED,
    AST_ERROR_KIND_SPECIAL_WORD_OR_REPETITION_UNEXPECTED_EOF,
    AST_ERROR_KIND_NEST_LIMIT_EXCEEDED, // unused by parser.c but kept for parity
} ast_ErrorKind_tag;

typedef struct ast_ErrorKind {
    ast_ErrorKind_tag tag;
    rs_Span           original; // valid only for *Duplicate / *RepeatedNegation
} ast_ErrorKind;

// Mirror of parser.c's local ast_Ast_tag enum (NOTE the order is NOT the
// same as the AstTag above — LOOKAROUND comes before GROUP here).
typedef enum {
    AST_TAG_EMPTY,
    AST_TAG_FLAGS,
    AST_TAG_LITERAL,
    AST_TAG_DOT,
    AST_TAG_TOP,
    AST_TAG_ASSERTION,
    AST_TAG_CLASS_UNICODE,
    AST_TAG_CLASS_PERL,
    AST_TAG_CLASS_BRACKETED,
    AST_TAG_REPETITION,
    AST_TAG_LOOKAROUND,
    AST_TAG_GROUP,
    AST_TAG_ALTERNATION,
    AST_TAG_CONCAT,
    AST_TAG_INTERSECTION,
    AST_TAG_COMPLEMENT,
} ast_Ast_tag;

typedef enum {
    AST_GROUP_KIND_CAPTURE_INDEX,
    AST_GROUP_KIND_CAPTURE_NAME,
    AST_GROUP_KIND_NON_CAPTURING,
    AST_GROUP_KIND_LOOKAROUND,
    AST_GROUP_KIND_COMPLEMENT,
} ast_GroupKind_tag;

typedef enum {
    AST_LOOKAROUND_POSITIVE_LOOKAHEAD,
    AST_LOOKAROUND_NEGATIVE_LOOKAHEAD,
    AST_LOOKAROUND_POSITIVE_LOOKBEHIND,
    AST_LOOKAROUND_NEGATIVE_LOOKBEHIND,
} ast_LookaroundKind;

typedef enum {
    AST_REPETITION_ZERO_OR_ONE,
    AST_REPETITION_ZERO_OR_MORE,
    AST_REPETITION_ONE_OR_MORE,
    AST_REPETITION_RANGE,
} ast_RepetitionKind_tag;

typedef enum {
    AST_REPETITION_RANGE_EXACTLY,
    AST_REPETITION_RANGE_AT_LEAST,
    AST_REPETITION_RANGE_BOUNDED,
} ast_RepetitionRange_tag;

typedef enum {
    AST_ASSERTION_START_TEXT,
    AST_ASSERTION_END_TEXT,
    AST_ASSERTION_START_LINE,
    AST_ASSERTION_END_LINE,
    AST_ASSERTION_WORD_BOUNDARY,
    AST_ASSERTION_NOT_WORD_BOUNDARY,
    AST_ASSERTION_WORD_BOUNDARY_START,
    AST_ASSERTION_WORD_BOUNDARY_END,
    AST_ASSERTION_WORD_BOUNDARY_START_ANGLE,
    AST_ASSERTION_WORD_BOUNDARY_END_ANGLE,
    AST_ASSERTION_WORD_BOUNDARY_START_HALF,
    AST_ASSERTION_WORD_BOUNDARY_END_HALF,
} ast_AssertionKind;

typedef enum {
    AST_FLAG_CASE_INSENSITIVE,
    AST_FLAG_MULTI_LINE,
    AST_FLAG_DOT_MATCHES_NEW_LINE,
    AST_FLAG_SWAP_GREED,
    AST_FLAG_UNICODE,
    AST_FLAG_CRLF,
    AST_FLAG_IGNORE_WHITESPACE,
} ast_Flag;

// ast_Ast is opaque outside ast.c.
typedef struct ast_Ast ast_Ast;

// ast_Lookaround layout.
typedef struct ast_Lookaround {
    ast_LookaroundKind kind;
    rs_Span            span;
    ast_Ast           *ast;
} ast_Lookaround;

// ast_RepetitionOp layout.
typedef struct ast_RepetitionOp {
    rs_Span                 span;
    ast_RepetitionKind_tag  kind;
    ast_RepetitionRange_tag range; // used iff kind==AST_REPETITION_RANGE
    uint32_t                lo;
    uint32_t                hi;
} ast_RepetitionOp;

// ---- ast_Concat: 128-byte ABI footprint preserved from the resharp-c port,
// where the same struct was passed across a stub TU boundary by value. ----
typedef struct ast_Concat {
    rs_Span   span;       // 48
    ast_Ast **asts;       //  8
    size_t    len;        //  8
    size_t    cap;        //  8
    uint64_t  _pad[7];    // 56 -> 128 total
} ast_Concat;

typedef struct ast_Alternation {
    rs_Span   span;
    ast_Ast **asts;
    size_t    len;
    size_t    cap;
    uint64_t  _pad[7];
} ast_Alternation;

typedef struct ast_Intersection {
    rs_Span   span;
    ast_Ast **asts;
    size_t    len;
    size_t    cap;
    uint64_t  _pad[7];
} ast_Intersection;

typedef struct ast_Complement {
    rs_Span   span;       // 48
    ast_Ast  *ast;        //  8
    uint64_t  _pad[9];    // 72 -> 128 total
} ast_Complement;

// CaptureName: span + name(string) + index.  128 bytes total.
typedef struct ast_CaptureName {
    rs_Span   span;       // 48
    char     *name;       //  8  — heap-owned NUL-terminated
    size_t    name_len;   //  8
    size_t    name_cap;   //  8
    uint32_t  index;      //  4
    uint32_t  _pad32;     //  4
    uint64_t  _pad[6];    // 48 -> 128 total
} ast_CaptureName;

// ast_FlagsItem: span + kind tag + Flag value.  128 bytes total.
typedef struct ast_FlagsItem {
    rs_Span   span;       // 48
    int       is_negation;//  4 — bool: 1 = negation, 0 = flag
    ast_Flag  flag;       //  4 — valid iff !is_negation
    uint64_t  _pad[9];    // 72 -> 128 total
} ast_FlagsItem;

// ast_Flags: span + items vec.  128 bytes total.
typedef struct ast_Flags {
    rs_Span         span;     // 48
    ast_FlagsItem  *items;    //  8
    size_t          len;      //  8
    size_t          cap;      //  8
    uint64_t        _pad[7];  // 56 -> 128 total
} ast_Flags;

// ast_SetFlags: span + inline flags (without nested rs_Span).  128B total.
typedef struct ast_SetFlags {
    rs_Span         span;       // 48
    ast_FlagsItem  *items;      //  8
    size_t          items_len;  //  8
    size_t          items_cap;  //  8
    rs_Span         flags_span; // 48 -> 120
    uint64_t        _pad[1];    //  8 -> 128 total
} ast_SetFlags;

// ast_Group: heap-allocate per-kind payload to keep the header at 128B.
typedef struct ast_GroupCaptureName {
    uint32_t index;
    uint8_t  starts_with_p;
    rs_Span  name_span;
    char    *name;
    size_t   name_len;
    size_t   name_cap;
} ast_GroupCaptureName;

typedef struct ast_GroupNonCapturing {
    rs_Span         span;
    ast_FlagsItem  *items;
    size_t          len;
    size_t          cap;
} ast_GroupNonCapturing;

typedef struct ast_Group {
    rs_Span             span;            // 48
    ast_GroupKind_tag   kind_tag;        //  4
    uint32_t            _pad32;          //  4
    ast_Ast            *ast;             //  8
    // Heap-owned per-kind payload, nullptr when not applicable.
    void               *payload;         //  8
    // Inline scalars used by some kinds.
    uint32_t            capture_index;   //  4 — valid for CAPTURE_INDEX
    ast_LookaroundKind  lookaround_kind; //  4 — valid for LOOKAROUND
    uint64_t            _pad[6];         // 48 -> 128 total
} ast_Group;

// ast_Repetition: span + op + greedy + ast.  128 bytes total.
typedef struct ast_Repetition {
    rs_Span                 span;       // 48
    rs_Span                 op_span;    // 48
    ast_RepetitionKind_tag  kind;       //  4
    ast_RepetitionRange_tag range;      //  4
    uint32_t                lo;         //  4
    uint32_t                hi;         //  4
    ast_Ast                *ast;        //  8
    uint8_t                 greedy;     //  1
    uint8_t                 _pad8[7];   //  7 -> 128 total
} ast_Repetition;

// ast_Assertion: concrete layout `{rs_Span span; int kind;}`.
typedef struct ast_Assertion {
    rs_Span span;
    int     kind; // ast_AssertionKind
} ast_Assertion;

// ast_Comment: concrete layout `{rs_Span span; char *comment; uint64_t _stub[14];}`.
typedef struct ast_Comment {
    rs_Span  span;        // 48
    char    *comment;     //  8
    uint64_t _stub[14];   // 112 -> 168 total
} ast_Comment;

// ---------------------------------------------------------------------------
// Function declarations
// ---------------------------------------------------------------------------

// --- ast_Ast ---
// Each `_owned` constructor allocates exactly one ast_Ast.  When the
// caller has a per-regex pool (RegexBuilder->allocator / parser->allocator),
// pass it in to route the allocation through that pool; nullptr falls
// back to the runtime default arena.
ast_Ast       *ast_Ast_empty_owned(rs_Span span, n00b_allocator_t *allocator);
ast_Ast       *ast_Ast_dot_owned(rs_Span span, n00b_allocator_t *allocator);
ast_Ast       *ast_Ast_top_owned(rs_Span span, n00b_allocator_t *allocator);
ast_Ast       *ast_Ast_literal_owned(rs_Literal lit, n00b_allocator_t *allocator);
ast_Ast       *ast_Ast_assertion_owned(ast_Assertion a, n00b_allocator_t *allocator);
ast_Ast       *ast_Ast_class_perl_owned(rs_ClassPerl c, n00b_allocator_t *allocator);
ast_Ast       *ast_Ast_class_unicode_owned(rs_ClassUnicode c, n00b_allocator_t *allocator);
ast_Ast       *ast_Ast_class_bracketed_owned(rs_ClassBracketed c, n00b_allocator_t *allocator);
ast_Ast       *ast_Ast_flags_owned(ast_SetFlags f, n00b_allocator_t *allocator);
ast_Ast       *ast_Ast_repetition_owned(ast_Repetition r, n00b_allocator_t *allocator);
ast_Ast       *ast_Ast_group_owned(ast_Group g, n00b_allocator_t *allocator);
ast_Ast       *ast_Ast_alternation_owned(ast_Alternation a, n00b_allocator_t *allocator);
ast_Ast       *ast_Ast_intersection_owned(ast_Intersection i, n00b_allocator_t *allocator);
ast_Ast       *ast_Ast_complement_owned(ast_Complement c, n00b_allocator_t *allocator);
ast_Ast       *ast_Ast_lookaround_owned(ast_Lookaround l, n00b_allocator_t *allocator);
ast_Ast       *ast_Ast_concat_owned(ast_Concat c, n00b_allocator_t *allocator);
void           ast_Ast_free(ast_Ast *a);
const rs_Span *ast_Ast_span(const ast_Ast *a);
rs_Span        ast_Ast_span_with_end(const ast_Ast *a, rs_Position end);
ast_Ast_tag    ast_Ast_tag_of(const ast_Ast *a);

const rs_Literal       *ast_Ast_as_literal(const ast_Ast *a);
const rs_ClassPerl     *ast_Ast_as_class_perl(const ast_Ast *a);
const rs_ClassUnicode  *ast_Ast_as_class_unicode(const ast_Ast *a);
const rs_ClassBracketed*ast_Ast_as_class_bracketed(const ast_Ast *a);
const ast_Group        *ast_Ast_as_group(const ast_Ast *a);
const ast_Concat       *ast_Ast_as_concat(const ast_Ast *a);
const ast_Alternation  *ast_Ast_as_alternation(const ast_Ast *a);
const ast_Intersection *ast_Ast_as_intersection(const ast_Ast *a);
const ast_Complement   *ast_Ast_as_complement(const ast_Ast *a);
const ast_Lookaround   *ast_Ast_as_lookaround(const ast_Ast *a);
const ast_Repetition   *ast_Ast_as_repetition(const ast_Ast *a);
const ast_SetFlags     *ast_Ast_as_flags(const ast_Ast *a);
const ast_Assertion    *ast_Ast_as_assertion(const ast_Ast *a);

// --- ast_Concat ---
ast_Concat      ast_Concat_new(rs_Span span);
size_t          ast_Concat_count(const ast_Concat *c);
const ast_Ast  *ast_Concat_get(const ast_Concat *c, size_t i);
ast_Ast        *ast_Concat_into_ast_owned(ast_Concat c, n00b_allocator_t *allocator);
void            ast_Concat_push_ast(ast_Concat *c, ast_Ast *a, n00b_allocator_t *allocator);
ast_Ast        *ast_Concat_pop_ast(ast_Concat *c);
void            ast_Concat_set_span_end(ast_Concat *c, rs_Position end);
rs_Position     ast_Concat_span_start(const ast_Concat *c);
rs_Position     ast_Concat_span_end(const ast_Concat *c);

// --- ast_Alternation ---
ast_Alternation ast_Alternation_new(rs_Span span);
size_t          ast_Alternation_count(const ast_Alternation *a);
const ast_Ast  *ast_Alternation_get(const ast_Alternation *a, size_t i);
ast_Ast        *ast_Alternation_into_ast_owned(ast_Alternation a, n00b_allocator_t *allocator);
void            ast_Alternation_push_ast(ast_Alternation *a, ast_Ast *e, n00b_allocator_t *allocator);
void            ast_Alternation_set_span_end(ast_Alternation *a, rs_Position end);
rs_Span         ast_Alternation_span(const ast_Alternation *a);

// --- ast_Intersection ---
ast_Intersection ast_Intersection_new(rs_Span span);
size_t           ast_Intersection_count(const ast_Intersection *i);
const ast_Ast   *ast_Intersection_get(const ast_Intersection *i, size_t k);
ast_Ast         *ast_Intersection_into_ast_owned(ast_Intersection i, n00b_allocator_t *allocator);
void             ast_Intersection_push_ast(ast_Intersection *i, ast_Ast *e, n00b_allocator_t *allocator);
void             ast_Intersection_set_span_end(ast_Intersection *i, rs_Position end);
rs_Span          ast_Intersection_span(const ast_Intersection *i);

// --- ast_Complement ---
ast_Complement   ast_Complement_new(rs_Span span, ast_Ast *body);
const ast_Ast   *ast_Complement_inner(const ast_Complement *c);

// --- ast_Lookaround ---
const ast_Ast      *ast_Lookaround_inner(const ast_Lookaround *l);
ast_LookaroundKind  ast_Lookaround_kind(const ast_Lookaround *l);
rs_Span             ast_Lookaround_span(const ast_Lookaround *l);

// --- ast_Group ---
ast_Group          ast_Group_new_capture_index(rs_Span open_span, uint32_t idx,
                                               rs_Span inner_span);
ast_Group          ast_Group_new_capture_name(rs_Span open_span, bool starts_with_p,
                                              ast_CaptureName name,
                                              rs_Span inner_span);
ast_Group          ast_Group_new_non_capturing(rs_Span open_span, ast_Flags flags,
                                               rs_Span inner_span);
ast_Group          ast_Group_new_lookaround(rs_Span open_span,
                                            ast_LookaroundKind kind,
                                            rs_Span inner_span);
ast_Group          ast_Group_new_complement(rs_Span open_span, rs_Span inner_span);
const ast_Ast     *ast_Group_inner(const ast_Group *g);
const ast_Flags   *ast_Group_flags(const ast_Group *g);
bool               ast_Group_kind_is_complement(const ast_Group *g);
bool               ast_Group_kind_is_non_capturing(const ast_Group *g);
const ast_Flags   *ast_Group_kind_non_capturing_flags(const ast_Group *g);
void               ast_Group_set_span_end(ast_Group *g, rs_Position end);
void               ast_Group_set_ast(ast_Group *g, ast_Ast *a);
ast_Ast           *ast_Group_take_ast(ast_Group *g);
rs_Span            ast_Group_span(const ast_Group *g);

// --- ast_Repetition ---
ast_Repetition          ast_Repetition_make(rs_Span span,
                                            rs_Span op_span,
                                            ast_RepetitionKind_tag kind,
                                            uint32_t lo, uint32_t hi,
                                            ast_RepetitionRange_tag range,
                                            ast_Ast *body);
const ast_Ast          *ast_Repetition_inner(const ast_Repetition *r);
ast_RepetitionKind_tag  ast_Repetition_op_kind_tag(const ast_Repetition *r);
ast_RepetitionRange_tag ast_Repetition_op_range_tag(const ast_Repetition *r);
void                    ast_Repetition_op_range_bounds(const ast_Repetition *r,
                                                       uint32_t *lo, uint32_t *hi);

// --- ast_Assertion ---
ast_AssertionKind ast_Assertion_kind(const ast_Assertion *a);
rs_Span           ast_Assertion_span_get(const ast_Assertion *a);

// --- ast_CaptureName ---
ast_CaptureName   ast_CaptureName_make(rs_Span span, char *name_owned, uint32_t index);
const char       *ast_CaptureName_name(const ast_CaptureName *c);
rs_Span           ast_CaptureName_span(const ast_CaptureName *c);

// --- ast_ClassPerl / ast_ClassUnicode / ast_Literal ---
rs_ClassPerlKind  ast_ClassPerl_kind(const rs_ClassPerl *c);
bool              ast_ClassPerl_negated(const rs_ClassPerl *c);
bool              ast_ClassUnicode_negated(const rs_ClassUnicode *c);
uint32_t          ast_Literal_char(const rs_Literal *l);

// --- ast_Comment ---
void              ast_Comment_set_text(ast_Comment *c, char *text);

// --- ast_Flags / ast_SetFlags / ast_FlagsItem ---
ast_Flags         ast_Flags_new(rs_Span span);
int               ast_Flags_add_item(ast_Flags *f, ast_FlagsItem item,
                                       n00b_allocator_t *allocator);
int               ast_Flags_flag_state(const ast_Flags *f, ast_Flag flag);
ast_FlagsItem     ast_Flags_get_item(const ast_Flags *f, size_t i);
bool              ast_Flags_is_empty(const ast_Flags *f);
bool              ast_Flags_items_empty(const ast_Flags *f);
void              ast_Flags_set_span_end(ast_Flags *f, rs_Position end);

ast_FlagsItem     ast_FlagsItem_negation(rs_Span span);
ast_FlagsItem     ast_FlagsItem_flag(rs_Span span, ast_Flag flag);
rs_Span           ast_FlagsItem_span(const ast_FlagsItem *fi);

ast_SetFlags      ast_SetFlags_make(rs_Span span, ast_Flags flags);
int               ast_SetFlags_flag_state(const ast_SetFlags *f, ast_Flag flag);
rs_Span           ast_SetFlags_span(const ast_SetFlags *f);

// =========================================================================
// regex_syntax (rs_*) function declarations — implemented in regex_syntax.c
// =========================================================================

// --- Span / Position ---
rs_Span     rs_Span_new(rs_Position start, rs_Position end);
rs_Span     rs_Span_splat(rs_Position p);
rs_Span     rs_Span_combine(rs_Position start, rs_Position end);
rs_Position rs_Position_new(size_t offset, size_t line, size_t column);

// --- Literal ---
rs_Literal       rs_Literal_make(rs_Span span, rs_LiteralKind kind, uint32_t c);
rs_Literal       rs_Literal_make_special(rs_Span span, rs_SpecialLiteralKind sk, uint32_t c);
rs_Literal       rs_Literal_make_hex_fixed(rs_Span span, rs_HexLiteralKind hk, uint32_t c);
rs_Literal       rs_Literal_make_hex_brace(rs_Span span, rs_HexLiteralKind hk, uint32_t c);
rs_Literal       rs_Literal_make_octal(rs_Span span, uint32_t c);
void             rs_Literal_set_span_start(rs_Literal *l, rs_Position start);
const rs_Span   *rs_Literal_span(const rs_Literal *l);
rs_Literal       rs_Literal_clone(const rs_Literal *l);

// --- HexLiteralKind ---
size_t           rs_HexLiteralKind_digits(rs_HexLiteralKind k);

// --- ClassPerl ---
rs_ClassPerl     rs_ClassPerl_make(rs_Span span, rs_ClassPerlKind kind, bool negated);
void             rs_ClassPerl_set_span_start(rs_ClassPerl *c, rs_Position start);
const rs_Span   *rs_ClassPerl_span(const rs_ClassPerl *c);

// --- ClassUnicode ---
rs_ClassUnicode  rs_ClassUnicode_make_named(rs_Span span, bool negated, char *name_owned);
rs_ClassUnicode  rs_ClassUnicode_make_named_value(rs_Span span, bool negated,
                                                  rs_ClassUnicodeOpKind op,
                                                  char *name_owned, char *value_owned);
rs_ClassUnicode  rs_ClassUnicode_make_one_letter(rs_Span span, bool negated, uint32_t c);
void             rs_ClassUnicode_set_span_start(rs_ClassUnicode *c, rs_Position start);
const rs_Span   *rs_ClassUnicode_span(const rs_ClassUnicode *c);
rs_ClassUnicode  rs_ClassUnicode_clone(const rs_ClassUnicode *c);
const char      *rs_ClassUnicode_named(const rs_ClassUnicode *c, size_t *len);

// --- ClassAscii ---
rs_ClassAscii    rs_ClassAscii_make(rs_Span span, int kind, bool negated);
bool             rs_ClassAsciiKind_from_name(const char *name, size_t n, int *out_kind);

// --- ClassBracketed ---
rs_ClassBracketed rs_ClassBracketed_make(rs_Span span, bool negated, rs_ClassSet kind);
void              rs_ClassBracketed_set_span_end(rs_ClassBracketed *b, rs_Position end);
void              rs_ClassBracketed_set_kind(rs_ClassBracketed *b, rs_ClassSet kind);
rs_Span           rs_ClassBracketed_span(const rs_ClassBracketed *b);
bool              rs_ClassBracketed_negated(const rs_ClassBracketed *b);
rs_ClassSet       rs_ClassBracketed_kind_get(const rs_ClassBracketed *b);
rs_ClassBracketed rs_ClassBracketed_clone(const rs_ClassBracketed *b);

// --- ClassSet ---
rs_ClassSet     rs_ClassSet_item(rs_ClassSetItem item);
rs_ClassSet     rs_ClassSet_union_(rs_ClassSetUnion u);
rs_ClassSet     rs_ClassSet_binary_op(rs_ClassSetBinaryOpKind kind,
                                      rs_ClassSet lhs,
                                      rs_ClassSet rhs,
                                      rs_Span span);
rs_Span         rs_ClassSet_span(const rs_ClassSet *s);
bool            rs_ClassSet_is_item(const rs_ClassSet *s);
rs_ClassSetItem rs_ClassSet_get_item(const rs_ClassSet *s);

// --- ClassSetItem ---
rs_ClassSetItem rs_ClassSetItem_literal(rs_Literal l);
rs_ClassSetItem rs_ClassSetItem_perl(rs_ClassPerl c);
rs_ClassSetItem rs_ClassSetItem_unicode(rs_ClassUnicode c);
rs_ClassSetItem rs_ClassSetItem_ascii(rs_ClassAscii a);
rs_ClassSetItem rs_ClassSetItem_range(rs_ClassSetRange r);
rs_ClassSetItem rs_ClassSetItem_bracketed(rs_ClassBracketed b);
bool            rs_ClassSetItem_is_perl(const rs_ClassSetItem *i);
rs_ClassPerl    rs_ClassSetItem_as_perl(const rs_ClassSetItem *i);
bool            rs_ClassSetItem_is_union(const rs_ClassSetItem *i);
size_t          rs_ClassSetItem_union_len(const rs_ClassSetItem *i);
const rs_ClassSetItem *rs_ClassSetItem_union_at(const rs_ClassSetItem *i, size_t k);

// --- ClassSetRange ---
rs_ClassSetRange rs_ClassSetRange_make(rs_Span span, rs_Literal start, rs_Literal end);
bool             rs_ClassSetRange_is_valid(const rs_ClassSetRange *r);

// --- ClassSetUnion ---
rs_ClassSetUnion rs_ClassSetUnion_new(rs_Span span);
void             rs_ClassSetUnion_push(rs_ClassSetUnion *u, rs_ClassSetItem item);
rs_ClassSetItem  rs_ClassSetUnion_into_item(rs_ClassSetUnion u);
bool             rs_ClassSetUnion_is_empty(const rs_ClassSetUnion *u);
rs_Position      rs_ClassSetUnion_span_start(const rs_ClassSetUnion *u);

// --- Ast (regex_syntax) ---
typedef struct rs_Ast rs_Ast;
rs_Ast *rs_Ast_literal_owned(rs_Literal lit);
rs_Ast *rs_Ast_class_unicode_owned(rs_ClassUnicode cls);
rs_Ast *rs_Ast_class_bracketed_owned(rs_ClassBracketed cls);
void    rs_Ast_free(rs_Ast *a);

// --- TranslatorBuilder / Translator ---
rs_TranslatorBuilder rs_TranslatorBuilder_new(void);
void                 rs_TranslatorBuilder_unicode(rs_TranslatorBuilder *b, bool v);
void                 rs_TranslatorBuilder_utf8(rs_TranslatorBuilder *b, bool v);
void                 rs_TranslatorBuilder_case_insensitive(rs_TranslatorBuilder *b, bool v);
rs_Translator        rs_TranslatorBuilder_build(rs_TranslatorBuilder *b);
bool                 rs_Translator_translate(rs_Translator *t, const char *pattern,
                                             const rs_Ast *ast, rs_Hir **out);
void                 rs_Translator_free(rs_Translator *t);

// --- Hir ---
// NOTE: rs_Hir_kind / rs_Hir_class_tag return enum types whose canonical
// declarations live inside parser.c (rs_HirKindTag / rs_HirClassTag).  The
// implementations in regex_syntax.c use ABI-compatible local enums; we do
// NOT redeclare those two functions here to avoid type-mismatch errors.
const uint8_t *rs_Hir_literal_bytes(const rs_Hir *h, size_t *len);
size_t         rs_Hir_class_unicode_ranges(const rs_Hir *h,
                                           uint32_t *out_starts,
                                           uint32_t *out_ends, size_t cap);
size_t         rs_Hir_class_bytes_ranges(const rs_Hir *h,
                                         uint8_t *out_starts,
                                         uint8_t *out_ends, size_t cap);
size_t         rs_Hir_concat_count(const rs_Hir *h);
const rs_Hir  *rs_Hir_concat_child(const rs_Hir *h, size_t i);
rs_Hir        *rs_Hir_dot_any_char(void);
rs_Hir        *rs_Hir_dot_any_char_except_lf(void);
rs_Hir        *rs_Hir_dot_any_byte_except_lf(void);
void           rs_Hir_free(rs_Hir *h);

// --- Utf8Sequences ---
// rs_Utf8Range is declared once HERE (with a struct tag) so every TU sees
// the exact same type.  Earlier resharp-c revisions had each TU declare its
// own anonymous-vs-tagged variant; under clang LTO with strict-aliasing
// those count as DIFFERENT types for TBAA, and writes typed as one variant
// were assumed not to alias reads typed as the other, silently dropping
// byte-range stores and truncating UTF-8 continuation-byte ranges
// (0x80-0xBF) in negated character classes such as `[^%]+`.
typedef struct rs_Utf8Range {
    uint8_t start;
    uint8_t end;
} rs_Utf8Range;
rs_Utf8Sequences *rs_Utf8Sequences_new(uint32_t start, uint32_t end);
void              rs_Utf8Sequences_free(rs_Utf8Sequences *it);
bool              rs_Utf8Sequences_next(rs_Utf8Sequences *it,
                                        rs_Utf8Range *out, size_t *n_out);

#ifdef __cplusplus
} // extern "C"
#endif

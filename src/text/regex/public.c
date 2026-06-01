/*
 * src/text/regex/public.c
 *
 * Phase 9 — public n00b regex API.  Implements every symbol declared in
 * `include/text/regex/regex.h` (§ 4 of the port plan) as a thin wrapper
 * over the internal engine entry points landed by Phases 5–8.
 *
 * Design notes:
 *   - Every public function validates its inputs via `n00b_require` (D8).
 *   - Whole-input matchers return natural types (D1); a capacity-exceeded
 *     or other internal failure during the scan calls `n00b_panic` (D9).
 *   - `n00b_regex_new` returns `n00b_result_t(n00b_regex_t *)` whose
 *     `.err` carries an `n00b_regex_error_kind_t` value cast to int.  On
 *     failure, the thread-local detail (per D14) is populated with a
 *     human-readable diagnostic.
 *   - `n00b_regex_stream_chunk` returns `n00b_result_t(int)` (D1).  The
 *     plan § 4 reads "n00b_result_t(void)"-flavoured; in practice the
 *     existing `n00b_result_t(T)` macro requires a non-`void` payload, so
 *     this file uses `n00b_result_t(int)` consistent with the engine
 *     stream API.  The `.ok` value is unused on success.
 *
 * Marshaler carveout (D3 / D7, ratified 2026-05-10 during Phase 9
 * dispatch): n00b has no marshaler primitive at the C surface.  Save /
 * load are **out-of-scope** until that primitive lands; no
 * `n00b_regex_save` / `n00b_regex_load` are implemented here.
 */

#include "n00b.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h> // memcpy (D13)

#include "core/alloc.h"
#include "core/string.h"
#include "core/thread.h" // for n00b_thread_id used by core/lock_common.h
#include "core/runtime.h" // n00b_thread_self() macro dereferences rt->threads[]
#include "core/mutex.h"

#include "adt/list.h"
#include "adt/option.h"
#include "adt/result.h"

#include "util/assert.h"
#include "util/panic.h"

#include "internal/regex/regex.h"
#include "internal/regex/algebra.h"
#include "internal/regex/parser.h"
#include "internal/regex/engine.h"
#include "internal/regex/accel.h"
#include "internal/regex/fas.h"
#include "internal/regex/stream.h"

#include "text/regex/regex.h"

// ---------------------------------------------------------------------------
// Public wrapper type.
//
// The opaque public handle wraps a pointer to the engine-level `Regex`
// plus the original pattern string (for `n00b_regex_pattern`) and a
// `compiled` flag tracking whether `n00b_regex_compile` has run.
// ---------------------------------------------------------------------------

struct n00b_regex_t {
    Regex          *engine;
    n00b_string_t  *pattern_src;
    bool            compiled;
};

// ---------------------------------------------------------------------------
// Per-thread last-compile detail (D14).
//
// Set on every `n00b_regex_new` call — cleared at entry, populated on
// failure with a heap-owned diagnostic string.  Storage lives on
// `n00b_thread_record_t::regex_last_detail` so we obey the rule that
// thread-local state is declared in the central thread state block
// (no `_Thread_local` in n00b code).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Engine err -> public err kind translation.
// ---------------------------------------------------------------------------

static int engine_err_to_public(int engine_err)
{
    switch ((n00b_regex_engine_err_t)engine_err) {
    case N00B_REGEX_ENGINE_ERR_NONE:                return N00B_RE_ERR_OK;
    case N00B_REGEX_ENGINE_ERR_CAPACITY_EXCEEDED:   return N00B_RE_ERR_CAPACITY_EXCEEDED;
    case N00B_REGEX_ENGINE_ERR_UNSUPPORTED_PATTERN: return N00B_RE_ERR_PARSE;
    case N00B_REGEX_ENGINE_ERR_PARSE:               return N00B_RE_ERR_PARSE;
    case N00B_REGEX_ENGINE_ERR_ALGEBRA:             return N00B_RE_ERR_ALGEBRA;
    case N00B_REGEX_ENGINE_ERR_PATTERN_TOO_LARGE:   return N00B_RE_ERR_PATTERN_TOO_LARGE;
    }
    return N00B_RE_ERR_PARSE;
}

// ---------------------------------------------------------------------------
// Error-string accessors.
// ---------------------------------------------------------------------------

n00b_string_t *n00b_regex_err_str(int kind)
{
    const char *s;
    switch ((n00b_regex_error_kind_t)kind) {
    case N00B_RE_ERR_OK:                s = "ok"; break;
    case N00B_RE_ERR_PARSE:             s = "parse error"; break;
    case N00B_RE_ERR_ALGEBRA:           s = "algebra error"; break;
    case N00B_RE_ERR_CAPACITY_EXCEEDED: s = "DFA capacity exceeded"; break;
    case N00B_RE_ERR_PATTERN_TOO_LARGE: s = "pattern too large"; break;
    case N00B_RE_ERR_SERIALIZE:         s = "serialization error"; break;
    default:                            s = "unknown regex error"; break;
    }
    return n00b_string_from_cstr(s);
}

n00b_string_t *n00b_regex_err_detail(void)
{
    return n00b_thread_self()->record->regex_last_detail;
}

// ---------------------------------------------------------------------------
// Parse-error -> human-readable detail.
// ---------------------------------------------------------------------------

static const char *parse_error_kind_str(ast_ErrorKind_tag tag)
{
    switch (tag) {
    case AST_ERROR_KIND_CLASS_ESCAPE_INVALID:                   return "invalid class escape";
    case AST_ERROR_KIND_CLASS_RANGE_LITERAL:                    return "non-literal class range bound";
    case AST_ERROR_KIND_CLASS_RANGE_INVALID:                    return "invalid class range";
    case AST_ERROR_KIND_CLASS_UNCLOSED:                         return "unclosed character class";
    case AST_ERROR_KIND_GROUP_UNCLOSED:                         return "unclosed group";
    case AST_ERROR_KIND_GROUP_UNOPENED:                         return "unopened group";
    case AST_ERROR_KIND_GROUP_NAME_INVALID:                     return "invalid group name";
    case AST_ERROR_KIND_GROUP_NAME_EMPTY:                       return "empty group name";
    case AST_ERROR_KIND_GROUP_NAME_DUPLICATE:                   return "duplicate group name";
    case AST_ERROR_KIND_GROUP_NAME_UNEXPECTED_EOF:              return "unexpected EOF in group name";
    case AST_ERROR_KIND_FLAG_REPEATED_NEGATION:                 return "repeated flag negation";
    case AST_ERROR_KIND_FLAG_DUPLICATE:                         return "duplicate flag";
    case AST_ERROR_KIND_FLAG_UNRECOGNIZED:                      return "unrecognized flag";
    case AST_ERROR_KIND_FLAG_UNEXPECTED_EOF:                    return "unexpected EOF in flags";
    case AST_ERROR_KIND_FLAG_DANGLING_NEGATION:                 return "dangling flag negation";
    case AST_ERROR_KIND_REPETITION_MISSING:                     return "missing repetition operand";
    case AST_ERROR_KIND_REPETITION_COUNT_INVALID:               return "invalid repetition count";
    case AST_ERROR_KIND_REPETITION_COUNT_UNCLOSED:              return "unclosed repetition count";
    case AST_ERROR_KIND_REPETITION_COUNT_DECIMAL_EMPTY:         return "empty decimal in repetition count";
    case AST_ERROR_KIND_DECIMAL_EMPTY:                          return "empty decimal";
    case AST_ERROR_KIND_DECIMAL_INVALID:                        return "invalid decimal";
    case AST_ERROR_KIND_ESCAPE_UNEXPECTED_EOF:                  return "unexpected EOF after escape";
    case AST_ERROR_KIND_ESCAPE_HEX_INVALID:                     return "invalid hex escape";
    case AST_ERROR_KIND_ESCAPE_HEX_INVALID_DIGIT:               return "invalid hex digit in escape";
    case AST_ERROR_KIND_ESCAPE_HEX_EMPTY:                       return "empty hex escape";
    case AST_ERROR_KIND_ESCAPE_UNRECOGNIZED:                    return "unrecognized escape";
    case AST_ERROR_KIND_UNSUPPORTED_BACKREFERENCE:              return "backreference not supported";
    case AST_ERROR_KIND_UNSUPPORTED_LAZY_QUANTIFIER:            return "lazy quantifier not supported";
    case AST_ERROR_KIND_UNSUPPORTED_RESHARP_REGEX:              return "unsupported regex feature";
    case AST_ERROR_KIND_UNICODE_CLASS_INVALID:                  return "invalid unicode class";
    case AST_ERROR_KIND_CAPTURE_LIMIT_EXCEEDED:                 return "capture limit exceeded";
    case AST_ERROR_KIND_COMPLEMENT_GROUP_EXPECTED:              return "complement group expected";
    case AST_ERROR_KIND_SPECIAL_WORD_BOUNDARY_UNCLOSED:         return "unclosed special word boundary";
    case AST_ERROR_KIND_SPECIAL_WORD_BOUNDARY_UNRECOGNIZED:     return "unrecognized special word boundary";
    case AST_ERROR_KIND_SPECIAL_WORD_OR_REPETITION_UNEXPECTED_EOF: return "unexpected EOF in word boundary or repetition";
    case AST_ERROR_KIND_NEST_LIMIT_EXCEEDED:                    return "nest limit exceeded";
    }
    return "unknown parse error";
}

// Build "<kind> at offset <N>" as a fresh n00b_string_t.  Decimal-formats
// the offset inline (no libc).
static n00b_string_t *parse_error_to_detail(const ParseError *err)
{
    const char *kind = parse_error_kind_str(err->kind.tag);

    // Decimal-format err->span.start.offset (size_t).
    char        num[32];
    size_t      n        = err->span.start.offset;
    int         pos      = (int)sizeof(num);
    num[--pos] = '\0';
    if (n == 0) {
        num[--pos] = '0';
    } else {
        while (n > 0) {
            num[--pos] = (char)('0' + (n % 10));
            n /= 10;
        }
    }
    const char *num_p = &num[pos];

    // Total length: "<kind> at offset <N>".
    size_t kind_len = 0; while (kind[kind_len])  ++kind_len;
    size_t num_len  = 0; while (num_p[num_len])  ++num_len;
    const char *mid = " at offset ";
    size_t mid_len  = 0; while (mid[mid_len])    ++mid_len;

    size_t total = kind_len + mid_len + num_len;
    char  *buf   = n00b_alloc_array(char, total + 1);
    memcpy(buf,                       kind, kind_len);
    memcpy(buf + kind_len,            mid,  mid_len);
    memcpy(buf + kind_len + mid_len,  num_p, num_len);
    buf[total] = '\0';
    return n00b_string_from_raw(buf, (int64_t)total);
}

static n00b_string_t *engine_err_to_detail(n00b_regex_engine_err_t err)
{
    const char *s = n00b_regex_engine_err_str((int)err);
    return n00b_string_from_cstr(s);
}

// ---------------------------------------------------------------------------
// Build engine-level RegexOptions from public kwargs.
// ---------------------------------------------------------------------------

static UnicodeMode public_unicode_to_engine(n00b_regex_unicode_mode_t m)
{
    switch (m) {
    case N00B_RE_UNICODE_ASCII:      return UNICODE_MODE_ASCII;
    case N00B_RE_UNICODE_DEFAULT:    return UNICODE_MODE_DEFAULT;
    case N00B_RE_UNICODE_FULL:       return UNICODE_MODE_FULL;
    case N00B_RE_UNICODE_JAVASCRIPT: return UNICODE_MODE_JAVASCRIPT;
    }
    return UNICODE_MODE_DEFAULT;
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

n00b_result_t(n00b_regex_t *)
n00b_regex_new(n00b_string_t *pattern) _kargs
{
    bool                       case_insensitive      = false;
    bool                       multiline             = true;
    bool                       dot_matches_newline   = false;
    bool                       ignore_whitespace     = false;
    bool                       hardened              = false;
    bool                       unbounded_size        = false;
    bool                       precompile            = false;
    n00b_regex_unicode_mode_t  unicode               = N00B_RE_UNICODE_DEFAULT;
    size_t                     max_dfa_capacity      = N00B_RE_DEFAULT_MAX_DFA_CAP;
    uint32_t                   lookahead_context_max = 0;
    n00b_allocator_t          *allocator             = nullptr;
}
{
    (void)allocator; // Engine does not yet accept a custom allocator.

    n00b_thread_self()->record->regex_last_detail = nullptr;

    n00b_require(pattern != nullptr, "n00b_regex_new: pattern must not be NULL");

    // Engine options.
    RegexOptions opts = regex_options_default();
    opts.case_insensitive     = case_insensitive;
    opts.multiline            = multiline;
    opts.dot_matches_new_line = dot_matches_newline;
    opts.ignore_whitespace    = ignore_whitespace;
    opts.hardened             = hardened;
    opts.unbounded_size       = unbounded_size;
    opts.unicode              = public_unicode_to_engine(unicode);
    if (max_dfa_capacity != N00B_RE_DEFAULT_MAX_DFA_CAP) {
        opts.max_dfa_capacity = max_dfa_capacity;
    }
    if (lookahead_context_max != 0) {
        opts.lookahead_context_max = lookahead_context_max;
    }

    // Parser flags mirror the engine's PatternFlagsLayout.
    PatternFlags flags = PatternFlags_default();
    flags.unicode              = (opts.unicode != UNICODE_MODE_ASCII);
    flags.full_unicode         = (opts.unicode == UNICODE_MODE_FULL);
    flags.ascii_perl_classes   = (opts.unicode == UNICODE_MODE_JAVASCRIPT);
    flags.case_insensitive     = opts.case_insensitive;
    flags.dot_matches_new_line = opts.dot_matches_new_line;
    flags.multiline            = opts.multiline;
    flags.ignore_whitespace    = opts.ignore_whitespace;
    if (opts.unbounded_size) {
        flags.expanded_ast_limit = UINT64_MAX;
        flags.max_list_len       = SIZE_MAX;
    }

    RegexBuilder *b = regex_builder_new(nullptr);
    regex_builder_set_lookahead_context_max(b, opts.lookahead_context_max);

    ParseError *perr = nullptr;
    NodeId node = parser_parse_ast_with(b, pattern->data, &flags, &perr);
    if (perr != nullptr) {
        n00b_thread_self()->record->regex_last_detail = parse_error_to_detail(perr);
        ParseError_free(perr);
        n00b_free(perr);
        regex_builder_free(b);
        return n00b_result_err(n00b_regex_t *, N00B_RE_ERR_PARSE);
    }

    Regex *engine = n00b_alloc(Regex);
    n00b_regex_engine_err_t eerr = regex_from_node(b, node, opts, engine);
    if (eerr != N00B_REGEX_ENGINE_ERR_NONE) {
        n00b_thread_self()->record->regex_last_detail = engine_err_to_detail(eerr);
        n00b_free(engine);
        // regex_from_node already freed the builder on err.
        return n00b_result_err(n00b_regex_t *,
                               engine_err_to_public((int)eerr));
    }

    n00b_regex_t *re = n00b_alloc(n00b_regex_t);
    re->engine      = engine;
    re->pattern_src = pattern;
    re->compiled    = false;

    if (precompile) {
        n00b_mutex_lock(&engine->inner_lock);
        engine_LDFA_precompile(engine->inner->fwd, engine->inner->b,
                               (size_t)N00B_RE_DFA_THRESHOLD);
        n00b_mutex_unlock(&engine->inner_lock);
        re->compiled = true;
    }

    return n00b_result_ok(n00b_regex_t *, re);
}

// ---------------------------------------------------------------------------
// Common: panic helper for whole-input scan failures (D1 + D9).
// ---------------------------------------------------------------------------

[[noreturn]] static void panic_on_scan_err(const char *where,
                                            n00b_regex_engine_err_t err)
{
    n00b_panic("«#»: engine error «#»",
               n00b_string_from_cstr(where),
               n00b_string_from_cstr(n00b_regex_engine_err_str((int)err)));
}

// ---------------------------------------------------------------------------
// Whole-input matchers
// ---------------------------------------------------------------------------

bool n00b_regex_is_match(n00b_regex_t *re, n00b_string_t *input)
{
    n00b_require(re    != nullptr, "n00b_regex_is_match: re must not be NULL");
    n00b_require(input != nullptr, "n00b_regex_is_match: input must not be NULL");

    bool out = false;
    n00b_regex_engine_err_t err = regex_is_match(re->engine,
                                                  (const uint8_t *)input->data,
                                                  input->u8_bytes, &out);
    if (err != N00B_REGEX_ENGINE_ERR_NONE) {
        panic_on_scan_err("n00b_regex_is_match", err);
    }
    return out;
}

int64_t n00b_regex_count(n00b_regex_t *re, n00b_string_t *input)
{
    n00b_require(re    != nullptr, "n00b_regex_count: re must not be NULL");
    n00b_require(input != nullptr, "n00b_regex_count: input must not be NULL");

    size_t out = 0;
    n00b_regex_engine_err_t err = regex_count_all(re->engine,
                                                   (const uint8_t *)input->data,
                                                   input->u8_bytes, &out);
    if (err != N00B_REGEX_ENGINE_ERR_NONE) {
        panic_on_scan_err("n00b_regex_count", err);
    }
    return (int64_t)out;
}

n00b_list_t(n00b_regex_match_t) *
n00b_regex_matches(n00b_regex_t *re, n00b_string_t *input)
{
    n00b_require(re    != nullptr, "n00b_regex_matches: re must not be NULL");
    n00b_require(input != nullptr, "n00b_regex_matches: input must not be NULL");

    // Engine fills a list of internal `Match`; convert to public type.
    auto engine_matches = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    n00b_regex_engine_err_t err = regex_find_all(re->engine,
                                                  (const uint8_t *)input->data,
                                                  input->u8_bytes,
                                                  &engine_matches);
    if (err != N00B_REGEX_ENGINE_ERR_NONE) {
        panic_on_scan_err("n00b_regex_matches", err);
    }

    // Canonical idiom: populate a fully scan-info-threaded lvalue
    // first, then struct-copy into the heap-allocated return shell.
    n00b_list_t(n00b_regex_match_t) lst = n00b_list_new(n00b_regex_match_t);
    size_t n = n00b_list_len(engine_matches);
    for (size_t i = 0; i < n; ++i) {
        Match m = n00b_list_get(engine_matches, i);
        n00b_regex_match_t pm = {
            .start = (int64_t)m.start,
            .end   = (int64_t)m.end,
        };
        n00b_list_push(lst, pm);
    }
    n00b_list_free(engine_matches);

    n00b_list_t(n00b_regex_match_t) *out =
        n00b_alloc(n00b_list_t(n00b_regex_match_t));
    *out = lst;
    return out;
}

n00b_option_t(n00b_regex_match_t)
n00b_regex_anchored(n00b_regex_t *re, n00b_string_t *input)
{
    n00b_require(re    != nullptr, "n00b_regex_anchored: re must not be NULL");
    n00b_require(input != nullptr, "n00b_regex_anchored: input must not be NULL");

    bool  found = false;
    Match m     = {};
    n00b_regex_engine_err_t err = regex_find_anchored(re->engine,
                                                       (const uint8_t *)input->data,
                                                       input->u8_bytes,
                                                       &found, &m);
    if (err != N00B_REGEX_ENGINE_ERR_NONE) {
        panic_on_scan_err("n00b_regex_anchored", err);
    }
    if (!found) return n00b_option_none(n00b_regex_match_t);
    n00b_regex_match_t pm = { .start = (int64_t)m.start, .end = (int64_t)m.end };
    return n00b_option_set(n00b_regex_match_t, pm);
}

n00b_string_t *
n00b_regex_replace(n00b_regex_t *re, n00b_string_t *input,
                   n00b_string_t *replacement)
{
    n00b_require(re          != nullptr, "n00b_regex_replace: re must not be NULL");
    n00b_require(input       != nullptr, "n00b_regex_replace: input must not be NULL");
    n00b_require(replacement != nullptr, "n00b_regex_replace: replacement must not be NULL");

    auto engine_matches = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    n00b_regex_engine_err_t err = regex_find_all(re->engine,
                                                  (const uint8_t *)input->data,
                                                  input->u8_bytes,
                                                  &engine_matches);
    if (err != N00B_REGEX_ENGINE_ERR_NONE) {
        panic_on_scan_err("n00b_regex_replace", err);
    }

    size_t  in_len   = input->u8_bytes;
    size_t  rep_len  = replacement->u8_bytes;
    size_t  n        = n00b_list_len(engine_matches);

    if (n == 0) {
        n00b_list_free(engine_matches);
        return input;
    }

    // Compute total output length: in_len - sum(match_len) + n * rep_len.
    size_t total_match_len = 0;
    for (size_t i = 0; i < n; ++i) {
        Match m = n00b_list_get(engine_matches, i);
        total_match_len += (m.end - m.start);
    }
    size_t out_len = in_len - total_match_len + n * rep_len;

    char  *buf      = n00b_alloc_array(char, out_len + 1);
    size_t cursor   = 0;
    size_t prev_end = 0;
    for (size_t i = 0; i < n; ++i) {
        Match m = n00b_list_get(engine_matches, i);
        size_t pre_len = m.start - prev_end;
        if (pre_len > 0) {
            memcpy(buf + cursor, input->data + prev_end, pre_len);
            cursor += pre_len;
        }
        if (rep_len > 0) {
            memcpy(buf + cursor, replacement->data, rep_len);
            cursor += rep_len;
        }
        prev_end = m.end;
    }
    size_t tail_len = in_len - prev_end;
    if (tail_len > 0) {
        memcpy(buf + cursor, input->data + prev_end, tail_len);
        cursor += tail_len;
    }
    buf[cursor] = '\0';
    n00b_list_free(engine_matches);
    return n00b_string_from_raw(buf, (int64_t)out_len);
}

n00b_list_t(n00b_string_t *) *
n00b_regex_split(n00b_regex_t *re, n00b_string_t *input)
{
    n00b_require(re    != nullptr, "n00b_regex_split: re must not be NULL");
    n00b_require(input != nullptr, "n00b_regex_split: input must not be NULL");

    auto engine_matches = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    n00b_regex_engine_err_t err = regex_find_all(re->engine,
                                                  (const uint8_t *)input->data,
                                                  input->u8_bytes,
                                                  &engine_matches);
    if (err != N00B_REGEX_ENGINE_ERR_NONE) {
        panic_on_scan_err("n00b_regex_split", err);
    }

    // Canonical idiom: populate a fully scan-info-threaded lvalue
    // first, then struct-copy into the heap-allocated return shell.
    n00b_list_t(n00b_string_t *) lst = n00b_list_new(n00b_string_t *);
    size_t prev_end = 0;
    size_t n        = n00b_list_len(engine_matches);
    for (size_t i = 0; i < n; ++i) {
        Match m = n00b_list_get(engine_matches, i);
        size_t seg_len = m.start - prev_end;
        n00b_string_t *seg =
            n00b_string_from_raw(input->data + prev_end, (int64_t)seg_len);
        n00b_list_push(lst, seg);
        prev_end = m.end;
    }
    size_t tail_len = input->u8_bytes - prev_end;
    n00b_string_t *tail =
        n00b_string_from_raw(input->data + prev_end, (int64_t)tail_len);
    n00b_list_push(lst, tail);

    n00b_list_free(engine_matches);

    n00b_list_t(n00b_string_t *) *out =
        n00b_alloc(n00b_list_t(n00b_string_t *));
    *out = lst;
    return out;
}

// ---------------------------------------------------------------------------
// Compile / is-compiled
// ---------------------------------------------------------------------------

void n00b_regex_compile(n00b_regex_t *re) _kargs
{
    uint32_t max_states = N00B_RE_DFA_THRESHOLD;
}
{
    n00b_require(re != nullptr, "n00b_regex_compile: re must not be NULL");
    Regex *engine = re->engine;
    n00b_mutex_lock(&engine->inner_lock);
    engine_LDFA_precompile(engine->inner->fwd, engine->inner->b,
                           (size_t)max_states);
    n00b_mutex_unlock(&engine->inner_lock);
    re->compiled = true;
}

bool n00b_regex_is_compiled(const n00b_regex_t *re)
{
    n00b_require(re != nullptr, "n00b_regex_is_compiled: re must not be NULL");
    return re->compiled;
}

// ---------------------------------------------------------------------------
// Streaming: whole-input shortest-match
// ---------------------------------------------------------------------------

typedef struct StreamPublicCtx {
    void (*on_match)(void *ctx, n00b_regex_match_t m);
    void *user_ctx;
} StreamPublicCtx;

static void stream_public_cb(void *ctx, Match m)
{
    StreamPublicCtx *sc = (StreamPublicCtx *)ctx;
    n00b_regex_match_t pm = { .start = (int64_t)m.start, .end = (int64_t)m.end };
    sc->on_match(sc->user_ctx, pm);
}

n00b_list_t(n00b_regex_match_t) *
n00b_regex_stream(n00b_regex_t *re, n00b_string_t *input) _kargs
{
    n00b_regex_match_cb_t  on_match = nullptr;
    void                  *ctx      = nullptr;
}
{
    n00b_require(re    != nullptr, "n00b_regex_stream: re must not be NULL");
    n00b_require(input != nullptr, "n00b_regex_stream: input must not be NULL");

    if (on_match != nullptr) {
        StreamPublicCtx sc = { .on_match = on_match, .user_ctx = ctx };
        n00b_result_t(int) res = regex_stream_with(re->engine,
                                                    (const uint8_t *)input->data,
                                                    input->u8_bytes,
                                                    stream_public_cb, &sc);
        if (n00b_result_is_err(res)) {
            panic_on_scan_err("n00b_regex_stream",
                              (n00b_regex_engine_err_t)n00b_result_get_err(res));
        }
        // Canonical idiom: build the list as a fully scan-info-threaded
        // lvalue, then struct-copy into the heap-allocated return shell.
        n00b_list_t(n00b_regex_match_t) empty_lst =
            n00b_list_new(n00b_regex_match_t);
        n00b_list_t(n00b_regex_match_t) *empty =
            n00b_alloc(n00b_list_t(n00b_regex_match_t));
        *empty = empty_lst;
        return empty;
    }

    // Collect into a list of internal Match, then convert.
    auto engine_matches = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    n00b_result_t(int) res = regex_stream(re->engine,
                                           (const uint8_t *)input->data,
                                           input->u8_bytes,
                                           &engine_matches);
    if (n00b_result_is_err(res)) {
        panic_on_scan_err("n00b_regex_stream",
                          (n00b_regex_engine_err_t)n00b_result_get_err(res));
    }
    // Canonical idiom: populate a fully scan-info-threaded lvalue
    // first, then struct-copy into the heap-allocated return shell.
    n00b_list_t(n00b_regex_match_t) lst = n00b_list_new(n00b_regex_match_t);
    size_t n = n00b_list_len(engine_matches);
    for (size_t i = 0; i < n; ++i) {
        Match m = n00b_list_get(engine_matches, i);
        n00b_regex_match_t pm = { .start = (int64_t)m.start, .end = (int64_t)m.end };
        n00b_list_push(lst, pm);
    }
    n00b_list_free(engine_matches);

    n00b_list_t(n00b_regex_match_t) *out =
        n00b_alloc(n00b_list_t(n00b_regex_match_t));
    *out = lst;
    return out;
}

// ---------------------------------------------------------------------------
// Cursor
// ---------------------------------------------------------------------------

struct n00b_regex_cursor_t {
    StreamState state;
};

n00b_regex_cursor_t *n00b_regex_cursor_new(n00b_regex_t *re)
{
    n00b_require(re != nullptr, "n00b_regex_cursor_new: re must not be NULL");
    (void)re; // re owns the eventual lock; not needed for cursor allocation
    n00b_regex_cursor_t *c = n00b_alloc(n00b_regex_cursor_t);
    c->state               = stream_state_new();
    return c;
}

n00b_regex_cursor_t *n00b_regex_cursor_at(n00b_regex_t *re, size_t offset)
{
    n00b_require(re != nullptr, "n00b_regex_cursor_at: re must not be NULL");
    (void)re;
    n00b_regex_cursor_t *c = n00b_alloc(n00b_regex_cursor_t);
    c->state               = stream_state_at(offset);
    return c;
}

size_t n00b_regex_cursor_pos(const n00b_regex_cursor_t *c)
{
    n00b_require(c != nullptr, "n00b_regex_cursor_pos: c must not be NULL");
    return stream_state_pos(&c->state);
}

// ---------------------------------------------------------------------------
// Streaming: chunked feed
// ---------------------------------------------------------------------------

n00b_result_t(int)
n00b_regex_stream_chunk(n00b_regex_t        *re,
                        const uint8_t       *chunk,
                        size_t               chunk_len,
                        n00b_regex_cursor_t *cursor,
                        void               (*on_end)(void *ctx, size_t end),
                        void                *ctx)
{
    n00b_require(re     != nullptr, "n00b_regex_stream_chunk: re must not be NULL");
    n00b_require(cursor != nullptr, "n00b_regex_stream_chunk: cursor must not be NULL");
    n00b_require(!(chunk == nullptr && chunk_len > 0),
                 "n00b_regex_stream_chunk: chunk must not be NULL when chunk_len > 0");

    StreamState out_state = {};
    n00b_result_t(int) res = regex_stream_chunk(re->engine, chunk, chunk_len,
                                                 cursor->state, &out_state,
                                                 on_end, ctx);
    if (n00b_result_is_err(res)) {
        return n00b_result_err(int,
                               engine_err_to_public(n00b_result_get_err(res)));
    }
    cursor->state = out_state;
    return n00b_result_ok(int, 0);
}

// ---------------------------------------------------------------------------
// Streaming: seek (fwd / rev)
// ---------------------------------------------------------------------------

n00b_option_t(n00b_regex_match_t)
n00b_regex_seek_fwd(n00b_regex_t        *re,
                    n00b_string_t       *input,
                    n00b_regex_cursor_t *cursor)
{
    n00b_require(re     != nullptr, "n00b_regex_seek_fwd: re must not be NULL");
    n00b_require(input  != nullptr, "n00b_regex_seek_fwd: input must not be NULL");
    n00b_require(cursor != nullptr, "n00b_regex_seek_fwd: cursor must not be NULL");

    size_t   pos        = stream_state_pos(&cursor->state);
    uint32_t state      = stream_state_state(&cursor->state);
    if (pos == 0 && state == 0) {
        state = REGEX_SEEK_INITIAL;
    }
    bool     found      = false;
    uint32_t out_state  = 0;
    size_t   out_end    = 0;
    n00b_result_t(int) res = regex_seek_fwd(re->engine,
                                             (const uint8_t *)input->data,
                                             input->u8_bytes,
                                             state, pos, &found,
                                             &out_state, &out_end);
    if (n00b_result_is_err(res)) {
        panic_on_scan_err("n00b_regex_seek_fwd",
                          (n00b_regex_engine_err_t)n00b_result_get_err(res));
    }
    if (!found) {
        // Advance cursor to end of input so subsequent calls are no-ops.
        cursor->state = stream_state_from_raw(out_state, input->u8_bytes);
        return n00b_option_none(n00b_regex_match_t);
    }
    cursor->state = stream_state_from_raw(out_state, out_end);
    n00b_regex_match_t pm = { .start = (int64_t)pos, .end = (int64_t)out_end };
    return n00b_option_set(n00b_regex_match_t, pm);
}

n00b_option_t(n00b_regex_match_t)
n00b_regex_seek_rev(n00b_regex_t        *re,
                    n00b_string_t       *input,
                    n00b_regex_cursor_t *cursor)
{
    n00b_require(re     != nullptr, "n00b_regex_seek_rev: re must not be NULL");
    n00b_require(input  != nullptr, "n00b_regex_seek_rev: input must not be NULL");
    n00b_require(cursor != nullptr, "n00b_regex_seek_rev: cursor must not be NULL");

    size_t   pos        = stream_state_pos(&cursor->state);
    uint32_t state      = stream_state_state(&cursor->state);
    if (state == 0 && pos == input->u8_bytes) {
        state = REGEX_SEEK_INITIAL;
    }
    bool     found      = false;
    uint32_t out_state  = 0;
    size_t   out_start  = 0;
    n00b_result_t(int) res = regex_seek_rev(re->engine,
                                             (const uint8_t *)input->data,
                                             input->u8_bytes,
                                             state, pos, &found,
                                             &out_state, &out_start);
    if (n00b_result_is_err(res)) {
        panic_on_scan_err("n00b_regex_seek_rev",
                          (n00b_regex_engine_err_t)n00b_result_get_err(res));
    }
    if (!found) {
        cursor->state = stream_state_from_raw(out_state, 0);
        return n00b_option_none(n00b_regex_match_t);
    }
    cursor->state = stream_state_from_raw(out_state, out_start);
    n00b_regex_match_t pm = { .start = (int64_t)out_start, .end = (int64_t)pos };
    return n00b_option_set(n00b_regex_match_t, pm);
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

n00b_string_t *n00b_regex_escape(n00b_string_t *literal)
{
    n00b_require(literal != nullptr, "n00b_regex_escape: literal must not be NULL");
    char *out = parser_escape(literal->data);
    return n00b_string_from_cstr(out);
}

n00b_string_t *n00b_regex_pattern(const n00b_regex_t *re)
{
    n00b_require(re != nullptr, "n00b_regex_pattern: re must not be NULL");
    return re->pattern_src;
}

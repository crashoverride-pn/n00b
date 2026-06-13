/**
 * @file include/text/regex/regex.h
 * @brief Public n00b regex API surface.
 *
 * Phase 9 of the regex port (see `~/dd/n00b_regex_port_plan.md` § 4).
 * This is the only n00b-regex header that uses the `n00b_*` symbol
 * prefix — everything in `include/internal/regex/` stays un-prefixed
 * because it is internal vocabulary.
 *
 * The compiled `n00b_regex_t` is opaque: callers see only a typedef'd
 * forward declaration here.  Construction is via `n00b_regex_new`,
 * which returns `n00b_result_t(n00b_regex_t *)`.  On failure, the
 * `result.err` carries the `n00b_regex_error_kind_t` value cast to
 * `int` (per D14); a thread-local detail set during compile and
 * cleared on the next compile call is exposed via
 * `n00b_regex_err_detail()`.
 *
 * Whole-input matchers (`n00b_regex_is_match`, `_count`, `_matches`,
 * `_anchored`, `_replace`, `_split`) return natural types (D1).  A
 * capacity-exceeded or other internal failure during the scan calls
 * `n00b_panic` (D9) rather than propagating an error code.
 *
 * Streaming (`_stream`, `_stream_chunk`) and seeking (`_seek_fwd`,
 * `_seek_rev`) have their own resumable cursor type.
 *
 * Companion source: `src/text/regex/public.c`.
 */
#pragma once

#include "n00b.h"
#include "core/string.h"
#include "core/alloc.h"
#include "adt/list.h"
#include "adt/result.h"
#include "adt/option.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// ---------------------------------------------------------------------------
// Error kinds + accessors  (D14: int err in n00b_result_t + side-channel)
// ---------------------------------------------------------------------------

/**
 * @brief Error kind carried in `n00b_result_t.err` from `n00b_regex_new`.
 */
typedef enum {
    N00B_RE_ERR_OK                 = 0,
    N00B_RE_ERR_PARSE              = 1,
    N00B_RE_ERR_ALGEBRA            = 2,
    N00B_RE_ERR_CAPACITY_EXCEEDED  = 3,
    N00B_RE_ERR_PATTERN_TOO_LARGE  = 4,
    N00B_RE_ERR_SERIALIZE          = 5,
} n00b_regex_error_kind_t;

/**
 * @brief Static generic message for an error kind.
 *
 * @param kind  `n00b_regex_error_kind_t` value cast to int (matches the
 *              `n00b_result_t.err` shape).
 * @return      Heap-owned `n00b_string_t *` (GC-managed).
 */
n00b_string_t *n00b_regex_err_str(int kind);

/**
 * @brief Thread-local detail set during the most recent compile attempt.
 *
 * Populated on every `n00b_regex_new` call (success or failure) — set to
 * `nullptr` on success, set to a heap-owned `n00b_string_t *` describing
 * the offending position / kind on failure.  Cleared at the start of
 * every `n00b_regex_new` call.
 *
 * @return  Last compile detail, or `nullptr` if the last compile
 *          succeeded (or no compile has run on this thread).
 */
n00b_string_t *n00b_regex_err_detail(void);

// ---------------------------------------------------------------------------
// Unicode mode
// ---------------------------------------------------------------------------

/**
 * @brief Unicode handling mode for pattern compilation.
 *
 * @note `N00B_RE_UNICODE_DEFAULT` enables UTF-8-aware character classes
 *       without full Unicode-property tables.  `_FULL` adds the property
 *       tables; `_JAVASCRIPT` selects ASCII-only `\d` / `\w` / `\s`.
 */
typedef enum {
    N00B_RE_UNICODE_ASCII      = 0,
    N00B_RE_UNICODE_DEFAULT    = 1,
    N00B_RE_UNICODE_FULL       = 2,
    N00B_RE_UNICODE_JAVASCRIPT = 3,
} n00b_regex_unicode_mode_t;

// ---------------------------------------------------------------------------
// Match record
// ---------------------------------------------------------------------------

/**
 * @brief Half-open byte-offset range `[start, end)` into the matched input.
 */
typedef struct {
    int64_t start;
    int64_t end;
} n00b_regex_match_t;

// ---------------------------------------------------------------------------
// Compiled regex (opaque; reach members via getters)
// ---------------------------------------------------------------------------

/**
 * @brief Opaque compiled regex handle.  Construct via `n00b_regex_new`.
 *
 * The underlying engine-level struct lives in
 * `include/internal/regex/regex.h` and is intentionally invisible to
 * callers of the public API.
 */
typedef struct n00b_regex_t n00b_regex_t;

/** @brief Default threshold for `n00b_regex_compile`'s DFA state cap. */
#define N00B_RE_DFA_THRESHOLD       10000u
/** @brief Sentinel meaning "engine default" for `max_dfa_capacity`. */
#define N00B_RE_DEFAULT_MAX_DFA_CAP 0u

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

/**
 * @brief Compile a regex pattern.
 *
 * On success returns `n00b_result_ok(n00b_regex_t *, re)`.  On failure
 * returns `n00b_result_err(n00b_regex_t *, kind)` where @c kind is an
 * `n00b_regex_error_kind_t` value cast to int; per-thread error detail
 * is available via `n00b_regex_err_detail()` until the next call.
 *
 * @param pattern             UTF-8 pattern string.
 *
 * @kw case_insensitive       Case-insensitive matching (default: false).
 * @kw multiline              `^` / `$` match line boundaries (default:
 *                            **true** — matches upstream resharp; this
 *                            **diverges** from PCRE / Python / JavaScript
 *                            conventions which default to false).
 * @kw dot_matches_newline    `.` matches `\n` (default: false).
 * @kw ignore_whitespace      Ignore unescaped whitespace in the pattern
 *                            (default: false).
 * @kw hardened               Disable rules that can blow up the DFA size
 *                            (default: false).
 * @kw unbounded_size         Allow unbounded DFA growth (default: false).
 * @kw precompile             Force full DFA at construction (default: false).
 * @kw unicode                Unicode mode (default:
 *                            `N00B_RE_UNICODE_DEFAULT`).
 * @kw max_dfa_capacity       Cap on lazy DFA states (default: engine
 *                            default — `N00B_RE_DEFAULT_MAX_DFA_CAP`).
 * @kw lookahead_context_max  Cap on lookaround context (default: 0 =
 *                            engine default).
 * @kw allocator              Allocator for the compiled regex (default:
 *                            runtime default, i.e. GC arena).
 */
n00b_result_t(n00b_regex_t *)
n00b_regex_new(n00b_string_t *pattern) _kargs {
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
};

// ---------------------------------------------------------------------------
// Whole-input matching (the 80% surface).
//
// Per D1: each function returns its natural type.  Internal failure
// during the scan (capacity exceeded, etc.) calls `n00b_panic` (D9)
// rather than propagating an error code.
// ---------------------------------------------------------------------------

/** @brief Boolean is-match over the whole input. */
bool n00b_regex_is_match(n00b_regex_t *re, n00b_string_t *input);

/** @brief Count of non-overlapping leftmost matches. */
int64_t n00b_regex_count(n00b_regex_t *re, n00b_string_t *input);

/** @brief List of every non-overlapping leftmost match. */
n00b_list_t(n00b_regex_match_t) *
n00b_regex_matches(n00b_regex_t *re, n00b_string_t *input);

/** @brief Anchored find: at most one match starting at offset 0. */
n00b_option_t(n00b_regex_match_t)
n00b_regex_anchored(n00b_regex_t *re, n00b_string_t *input);

/** @brief Replace every leftmost match with @p replacement. */
n00b_string_t *
n00b_regex_replace(n00b_regex_t *re, n00b_string_t *input,
                   n00b_string_t *replacement);

/** @brief Split @p input on every match; empty trailing field is included. */
n00b_list_t(n00b_string_t *) *
n00b_regex_split(n00b_regex_t *re, n00b_string_t *input);

// ---------------------------------------------------------------------------
// Compile (force full DFA expansion)
// ---------------------------------------------------------------------------

/**
 * @brief Eagerly expand the lazy DFA up to @p max_states new states.
 *
 * Subsequent matches reuse the precomputed transition table.  A no-op
 * when the DFA has already reached @p max_states.
 *
 * @kw max_states  Cap on newly-materialised states (default:
 *                 `N00B_RE_DFA_THRESHOLD`).
 */
void n00b_regex_compile(n00b_regex_t *re) _kargs {
    uint32_t max_states = N00B_RE_DFA_THRESHOLD;
};

/** @brief True iff the DFA has been compiled (precomputed). */
bool n00b_regex_is_compiled(const n00b_regex_t *re);

// ---------------------------------------------------------------------------
// Streaming (shortest-match, left-to-right)
// ---------------------------------------------------------------------------

/** @brief Per-match callback type for `n00b_regex_stream`. */
typedef void (*n00b_regex_match_cb_t)(void *ctx, n00b_regex_match_t m);

/**
 * @brief Whole-input shortest-match streamer.
 *
 * If @p on_match is non-null, each match is delivered via callback and
 * an empty list is returned (no list allocation).  Otherwise the
 * matches are collected into a returned list.
 *
 * @kw on_match  Per-match callback (default: nullptr).
 * @kw ctx       Opaque context passed to @p on_match (default: nullptr).
 */
n00b_list_t(n00b_regex_match_t) *
n00b_regex_stream(n00b_regex_t *re, n00b_string_t *input) _kargs {
    n00b_regex_match_cb_t  on_match = nullptr;
    void                  *ctx      = nullptr;
};

/**
 * @brief Resumable cursor for chunked input.
 *
 * Opaque.  Allocated once via `n00b_regex_cursor_new` or
 * `n00b_regex_cursor_at`, then threaded across `n00b_regex_stream_chunk`
 * / `n00b_regex_seek_fwd` / `n00b_regex_seek_rev` calls.
 */
typedef struct n00b_regex_cursor_t n00b_regex_cursor_t;

/** @brief Allocate a fresh cursor at offset 0. */
n00b_regex_cursor_t *n00b_regex_cursor_new(n00b_regex_t *re);

/** @brief Allocate a fresh cursor positioned at @p offset. */
n00b_regex_cursor_t *n00b_regex_cursor_at(n00b_regex_t *re, size_t offset);

/** @brief Current absolute offset of the cursor. */
size_t n00b_regex_cursor_pos(const n00b_regex_cursor_t *c);

/**
 * @brief Feed @p chunk_len bytes from @p chunk through the streaming
 *        DFA, advancing @p cursor in place.
 *
 * Each shortest-match end (in absolute input offsets) is delivered
 * via @p on_end.
 *
 * Streaming necessarily takes raw bytes; chunks may not align to UTF-8
 * codepoint boundaries.  Callers reading from `n00b_string_t` should
 * extract bytes via the string's underlying buffer.
 *
 * The returned `n00b_result_t(int)` carries an
 * `n00b_regex_error_kind_t` value cast to int in `.err`; on success the
 * Success value is 0 (unused).
 */
n00b_result_t(int)
n00b_regex_stream_chunk(n00b_regex_t        *re,
                        const uint8_t       *chunk,
                        size_t               chunk_len,
                        n00b_regex_cursor_t *cursor,
                        void               (*on_end)(void *ctx, size_t end),
                        void                *ctx);

// ---------------------------------------------------------------------------
// Seek (cursor scans over a contiguous buffer)
// ---------------------------------------------------------------------------

/**
 * @brief Advance @p cursor forward to the next match in @p input.
 *
 * Returns `n00b_option_set(...)` with the match on hit; the cursor's
 * position is advanced to the match end.  Returns `n00b_option_none(...)`
 * if no further match exists.
 */
n00b_option_t(n00b_regex_match_t)
n00b_regex_seek_fwd(n00b_regex_t        *re,
                    n00b_string_t       *input,
                    n00b_regex_cursor_t *cursor);

/**
 * @brief Advance @p cursor backward to the previous match in @p input.
 *
 * Returns `n00b_option_set(...)` with the match on hit; the cursor's
 * position is rewound to the match start.  Returns
 * `n00b_option_none(...)` if no further match exists.
 */
n00b_option_t(n00b_regex_match_t)
n00b_regex_seek_rev(n00b_regex_t        *re,
                    n00b_string_t       *input,
                    n00b_regex_cursor_t *cursor);

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/**
 * @brief Return @p literal with regex meta-characters backslash-escaped.
 *
 * The returned string is heap-owned (GC-managed).
 */
n00b_string_t *n00b_regex_escape(n00b_string_t *literal);

/**
 * @brief Return the original pattern source for @p re.
 *
 * The returned string is heap-owned (GC-managed) and equal to the
 * argument that was passed to `n00b_regex_new`.
 */
n00b_string_t *n00b_regex_pattern(const n00b_regex_t *re);

/**
 * @brief Return a compiled literal forward-prefix fact when one is available.
 *
 * This accessor reports only an obviously literal required prefix recovered
 * from the compiled regex graph. It does not parse, inspect, or reinterpret the
 * pattern source. Regexes whose compiled graph has no literal required prefix
 * return none.
 *
 * @param re Borrowed compiled regex handle.
 * @kw allocator Allocator for the returned prefix copy (default: nullptr,
 *               meaning runtime allocator).
 * @return Some(heap-owned prefix string) when a literal compiled prefix fact is
 *         available, otherwise none.
 */
n00b_option_t(n00b_string_t *)
n00b_regex_required_literal_prefix(const n00b_regex_t *re) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

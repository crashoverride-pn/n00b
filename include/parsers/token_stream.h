#pragma once

/**
 * @file token_stream.h
 * @brief Streaming token iteration with peek/rewind over a growable list.
 *
 * The token stream wraps a scanner and provides forward iteration,
 * lookahead (`peek`), lookback (`lookback`), rewind, save/restore,
 * random access by position, and reset (re-tokenize from scratch)
 * for speculative parsing — all over a position-indexed growable list.
 *
 * ### Usage
 *
 * ```c
 * n00b_token_stream_t *ts = n00b_token_stream_new(scanner);
 * n00b_stream_foreach(ts, tok) {
 *     printf("[%d] %s\n", tok->tid, tok->value);
 * }
 * n00b_token_stream_free(ts);
 * ```
 *
 * ### Related modules
 *
 * - `parsers/scanner.h` — scanner (token producer)
 * - `slay/token.h` — token types
 */

#include "parsers/scanner.h"

// ============================================================================
// Token stream struct
// ============================================================================

struct n00b_token_stream_t {
    n00b_scanner_t    *scanner;       /**< Produces tokens on demand. */

    // Token storage (growable, position-indexed)
    n00b_token_info_t **tokens;       /**< Pointer array of all tokens. */
    int32_t             token_cap;    /**< Allocated capacity. */
    int32_t             token_count;  /**< Number of tokens stored. */

    // Read position
    int32_t            pos;           /**< Current read cursor (absolute). */

    // Token indexing
    int32_t            next_index;    /**< Global token index counter. */

    // State
    bool               exhausted;     /**< True when scanner done + all consumed. */
};

// ============================================================================
// Lifecycle
// ============================================================================

/**
 * @brief Create a token stream wrapping a scanner.
 *
 * @param scanner The scanner that produces tokens.
 */
extern n00b_token_stream_t *
n00b_token_stream_new(n00b_scanner_t *scanner);

/**
 * @brief Free a token stream (does not free the scanner).
 * @param ts Token stream to free.
 */
extern void n00b_token_stream_free(n00b_token_stream_t *ts);

// ============================================================================
// Forward iteration
// ============================================================================

/**
 * @brief Get the next token and advance the position.
 *
 * Returns NULL when the stream is exhausted.
 * The returned pointer remains valid for the lifetime of the stream.
 */
extern n00b_token_info_t *n00b_stream_next(n00b_token_stream_t *ts);

/** @brief True if the stream has no more tokens. */
extern bool n00b_stream_is_done(n00b_token_stream_t *ts);

// ============================================================================
// Peek (lookahead)
// ============================================================================

/**
 * @brief Peek at a token N positions ahead of current without advancing.
 *
 * `n00b_stream_peek(ts, 0)` returns the token that `next()` would return.
 * Returns NULL if N exceeds available tokens.
 */
extern n00b_token_info_t *n00b_stream_peek(n00b_token_stream_t *ts, int32_t n);

// ============================================================================
// Rewind (lookback)
// ============================================================================

/**
 * @brief Move the read position back by N tokens.
 *
 * @return true on success, false if N exceeds available history.
 */
extern bool n00b_stream_rewind(n00b_token_stream_t *ts, int32_t n);

/**
 * @brief Peek at a token N positions behind current (already consumed).
 *
 * `n00b_stream_lookback(ts, 1)` returns the most recently consumed token.
 * Returns NULL if N exceeds available history.
 */
extern n00b_token_info_t *n00b_stream_lookback(n00b_token_stream_t *ts,
                                                int32_t n);

// ============================================================================
// Random access
// ============================================================================

/**
 * @brief Get token at absolute position, triggering lazy tokenization if needed.
 *
 * Returns NULL if the position is beyond EOF.
 */
extern n00b_token_info_t *n00b_stream_get(n00b_token_stream_t *ts, int32_t pos);

/**
 * @brief Total number of tokens stored so far.
 */
extern int32_t n00b_stream_token_count(n00b_token_stream_t *ts);

// ============================================================================
// Reset (re-tokenize from scratch)
// ============================================================================

/**
 * @brief Reset the stream: free all tokens, reset scanner, re-tokenize fresh.
 *
 * After reset the stream is at position 0 with no tokens cached.
 * This undoes any in-place token mutations (e.g., reclassify).
 */
extern void n00b_stream_reset(n00b_token_stream_t *ts);

// ============================================================================
// Save / restore (speculative parsing)
// ============================================================================

typedef struct {
    int32_t pos;  /**< Saved read position. */
} n00b_stream_mark_t;

/** @brief Save the current stream position. */
extern n00b_stream_mark_t n00b_stream_save(n00b_token_stream_t *ts);

/**
 * @brief Restore to a previously saved position.
 * @return false if the saved position is beyond current token count.
 */
extern bool n00b_stream_restore(n00b_token_stream_t *ts,
                                 n00b_stream_mark_t mark);

/** @brief Discard a save point (no-op, for symmetry / readability). */
static inline void
n00b_stream_commit(n00b_stream_mark_t mark)
{
    (void)mark;
}

// ============================================================================
// Collect all (drain to token list)
// ============================================================================

/**
 * @brief Drain the entire stream into an `n00b_list_t(n00b_token_info_t)`.
 *
 * Useful for parsers that need all tokens up front (e.g., Earley).
 * After this call the stream is exhausted.
 */
extern n00b_list_t(n00b_token_info_t) n00b_stream_collect(n00b_token_stream_t *ts);

// ============================================================================
// Array-backed stream (for tests and pre-tokenized input)
// ============================================================================

/**
 * @brief Create a token stream backed by a pre-built array of token pointers.
 *
 * The returned stream yields each token from the array in order.
 * The token pointers are borrowed; the caller must keep them alive
 * for the lifetime of the stream.
 *
 * @param tokens Array of token pointers.
 * @param count  Number of tokens in the array.
 * @return A new token stream.
 */
extern n00b_token_stream_t *
n00b_token_stream_from_array(n00b_token_info_t **tokens, int32_t count);

// ============================================================================
// Codepoint-level stream (for character-level grammars)
// ============================================================================

/**
 * @brief Create a token stream where each codepoint is its own token.
 *
 * Iterates over the UTF-8 bytes of @p input, producing one token per
 * codepoint.  Each token's `tid` is set to the codepoint value (so
 * the parser can match against `N00B_CHAR('x')` or `N00B_CLASS(...)` items).
 * A trailing EOF token is appended.
 *
 * @param input  The string to tokenize codepoint-by-codepoint.
 * @return A new token stream.
 */
extern n00b_token_stream_t *
n00b_token_stream_from_codepoints(n00b_string_t *input);

// ============================================================================
// Iteration macro
// ============================================================================

/**
 * @brief Iterate over all tokens in a stream.
 *
 * Usage:
 * ```c
 * n00b_stream_foreach(ts, tok) {
 *     printf("token: %s\n", tok->value);
 * }
 * ```
 *
 * Note: `tok_var` is declared as a block item BEFORE the loop (not in the
 * for-init) so ncc's gc-stack-maps transform can anchor it as a GC root — a
 * non-literal-initialized pointer declared in a for-init is an "unsupported
 * statement context" for the transform. As a result `tok_var` is scoped to the
 * enclosing block and remains in scope (== NULL) after the loop, and the macro
 * expands to two statements — so brace the body and use it at statement scope
 * (as shown), not as the lone statement of an unbraced `if`/`else`.
 */
#define n00b_stream_foreach(ts, tok_var)                       \
    n00b_token_info_t *(tok_var) = n00b_stream_next(ts);       \
    for (; (tok_var) != NULL; (tok_var) = n00b_stream_next(ts))

// test_lisp_tokenizer.c — Unit tests for the lisp tokenizer.

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "parsers/lisp_tokenizer.h"
#include "slay/token.h"

// ============================================================================
// Helpers
// ============================================================================

static n00b_token_stream_t *
tokenize_lisp(const char *src)
{
    n00b_buffer_t  *buf     = n00b_buffer_from_bytes((char *)src,
                                                       (int64_t)strlen(src));
    n00b_scanner_t *scanner = n00b_scanner_new(buf, n00b_lisp_tokenize, nullptr);

    return n00b_token_stream_new(scanner);
}

static int
drain_tokens(n00b_token_stream_t *ts, n00b_token_info_t **out, int max)
{
    int count = 0;

    while (count < max) {
        n00b_token_info_t *tok = n00b_stream_next(ts);

        if (!tok || tok->tid == N00B_TOK_EOF) {
            break;
        }

        if (out) {
            out[count] = tok;
        }

        count++;
    }

    return count;
}

// ============================================================================
// Test 1: Parentheses
// ============================================================================

static void
test_parens(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_lisp("()");
    int n = drain_tokens(ts, toks, 64);

    assert(n == 2);
    // ( and ) should have different hash-based IDs.
    assert(toks[0]->tid != toks[1]->tid);

    printf("  [PASS] parens\n");
}

// ============================================================================
// Test 2: Symbols
// ============================================================================

static void
test_symbols(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_lisp("(define x 42)");
    int n = drain_tokens(ts, toks, 64);

    // "(", "define", "x", "42", ")"
    assert(n == 5);

    printf("  [PASS] symbols\n");
}

// ============================================================================
// Test 3: String literals
// ============================================================================

static void
test_strings(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_lisp("(print \"hello\")");
    int n = drain_tokens(ts, toks, 64);

    // "(", "print", STRING_LIT, ")"
    assert(n == 4);

    printf("  [PASS] strings\n");
}

// ============================================================================
// Test 4: Number literals
// ============================================================================

static void
test_numbers(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_lisp("42 3.14");
    int n = drain_tokens(ts, toks, 64);

    assert(n >= 2);

    printf("  [PASS] numbers\n");
}

// ============================================================================
// Test 5: Comments
// ============================================================================

static void
test_comments(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_lisp("; comment\n(a)");
    int n = drain_tokens(ts, toks, 64);

    // "(", "a", ")"
    assert(n == 3);

    printf("  [PASS] comments\n");
}

// ============================================================================
// Test 6: Boolean literals (#t, #f)
// ============================================================================

static void
test_booleans(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_lisp("#t #f");
    int n = drain_tokens(ts, toks, 64);

    assert(n == 2);
    // #t and #f are different fixed-text terminals.
    assert(toks[0]->tid != toks[1]->tid);

    printf("  [PASS] booleans\n");
}

// ============================================================================
// Test 7: Nested expressions
// ============================================================================

static void
test_nested(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_lisp("(+ (* 2 3) 4)");
    int n = drain_tokens(ts, toks, 64);

    // "(", "+", "(", "*", "2", "3", ")", "4", ")"
    assert(n == 9);

    printf("  [PASS] nested\n");
}

// ============================================================================
// Test 8: Empty input
// ============================================================================

static void
test_empty(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_lisp("");
    int n = drain_tokens(ts, toks, 64);

    assert(n == 0);

    printf("  [PASS] empty\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    setbuf(stdout, nullptr);
    setbuf(stderr, nullptr);
    printf("Running lisp tokenizer tests...\n");

    test_parens();
    test_symbols();
    test_strings();
    test_numbers();
    test_comments();
    test_booleans();
    test_nested();
    test_empty();

    printf("All lisp tokenizer tests passed.\n");
    n00b_shutdown();
    return 0;
}

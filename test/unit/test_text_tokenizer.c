// test_text_tokenizer.c — Unit tests for the text tokenizer.

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "parsers/text_tokenizer.h"
#include "slay/token.h"

// ============================================================================
// Helpers
// ============================================================================

static n00b_token_stream_t *
tokenize_text(const char *src)
{
    n00b_buffer_t  *buf     = n00b_buffer_from_bytes((char *)src,
                                                       (int64_t)strlen(src));
    n00b_scanner_t *scanner = n00b_scanner_new(buf, n00b_text_tokenize, nullptr);

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
// Test 1: Identifiers
// ============================================================================

static void
test_identifiers(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_text("hello world");
    int n = drain_tokens(ts, toks, 64);

    assert(n == 2);
    assert(toks[0]->tid != 0);
    assert(toks[1]->tid != 0);

    printf("  [PASS] identifiers\n");
}

// ============================================================================
// Test 2: String literals
// ============================================================================

static void
test_string_literals(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_text("\"hello\" 'world'");
    int n = drain_tokens(ts, toks, 64);

    assert(n == 2);
    // Both should be STRING_LIT (same literal type ID).
    assert(toks[0]->tid == toks[1]->tid);

    printf("  [PASS] string_literals\n");
}

// ============================================================================
// Test 3: Number literals
// ============================================================================

static void
test_numbers(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_text("42 3.14 0xff");
    int n = drain_tokens(ts, toks, 64);

    assert(n >= 3);

    printf("  [PASS] numbers\n");
}

// ============================================================================
// Test 4: Punctuation
// ============================================================================

static void
test_punctuation(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_text("a + b");
    int n = drain_tokens(ts, toks, 64);

    // "a", "+", "b"
    assert(n == 3);

    printf("  [PASS] punctuation\n");
}

// ============================================================================
// Test 5: Whitespace is skipped
// ============================================================================

static void
test_whitespace_skipped(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_text("  a   b  ");
    int n = drain_tokens(ts, toks, 64);

    assert(n == 2);

    printf("  [PASS] whitespace_skipped\n");
}

// ============================================================================
// Test 6: Comments skipped
// ============================================================================

static void
test_comments_skipped(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_text("a // comment\nb /* block */ c");
    int n = drain_tokens(ts, toks, 64);

    assert(n == 3);  // a, b, c

    printf("  [PASS] comments_skipped\n");
}

// ============================================================================
// Test 7: Empty input
// ============================================================================

static void
test_empty_input(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_text("");
    int n = drain_tokens(ts, toks, 64);

    assert(n == 0);

    printf("  [PASS] empty_input\n");
}

// ============================================================================
// Test 8: Mixed content
// ============================================================================

static void
test_mixed(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_text("name = \"value\" + 42");
    int n = drain_tokens(ts, toks, 64);

    // "name", "=", "\"value\"", "+", "42" => 5 tokens
    assert(n == 5);

    printf("  [PASS] mixed\n");
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
    printf("Running text tokenizer tests...\n");

    test_identifiers();
    test_string_literals();
    test_numbers();
    test_punctuation();
    test_whitespace_skipped();
    test_comments_skipped();
    test_empty_input();
    test_mixed();

    printf("All text tokenizer tests passed.\n");
    n00b_shutdown();
    return 0;
}

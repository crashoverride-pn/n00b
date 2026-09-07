// test_json_tokenizer.c — Unit tests for the JSON tokenizer.

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "parsers/json_tokenizer.h"
#include "slay/token.h"

// ============================================================================
// Helpers
// ============================================================================

static n00b_token_stream_t *
tokenize_json(const char *src)
{
    n00b_buffer_t  *buf     = n00b_buffer_from_bytes((char *)src,
                                                       (int64_t)strlen(src));
    n00b_scanner_t *scanner = n00b_scanner_new(buf, n00b_json_tokenize, nullptr);

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
// Test 1: Structural characters
// ============================================================================

static void
test_structural(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_json("{}[]:,");
    int n = drain_tokens(ts, toks, 64);

    assert(n == 6);
    // Each should be a different token.
    assert(toks[0]->tid != toks[1]->tid);  // { vs }

    printf("  [PASS] structural\n");
}

// ============================================================================
// Test 2: String literals
// ============================================================================

static void
test_strings(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_json("\"hello\" \"world\"");
    int n = drain_tokens(ts, toks, 64);

    assert(n == 2);
    assert(toks[0]->tid == toks[1]->tid);  // Same literal type.

    printf("  [PASS] strings\n");
}

// ============================================================================
// Test 3: Numbers
// ============================================================================

static void
test_numbers(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_json("42 3.14 -17 1e10");
    int n = drain_tokens(ts, toks, 64);

    assert(n == 4);
    // All should be NUMBER type.
    assert(toks[0]->tid == toks[1]->tid);
    assert(toks[0]->tid == toks[2]->tid);
    assert(toks[0]->tid == toks[3]->tid);

    printf("  [PASS] numbers\n");
}

// ============================================================================
// Test 4: Keywords (true, false, null)
// ============================================================================

static void
test_keywords(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_json("true false null");
    int n = drain_tokens(ts, toks, 64);

    assert(n == 3);
    // Each keyword should have a different hash-based ID.
    assert(toks[0]->tid != toks[1]->tid);
    assert(toks[1]->tid != toks[2]->tid);

    printf("  [PASS] keywords\n");
}

// ============================================================================
// Test 5: Complete JSON object
// ============================================================================

static void
test_object(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_json("{\"key\": 42}");
    int n = drain_tokens(ts, toks, 64);

    // {, "key", :, 42, }
    assert(n == 5);

    printf("  [PASS] object\n");
}

// ============================================================================
// Test 6: Complete JSON array
// ============================================================================

static void
test_array(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_json("[1, 2, 3]");
    int n = drain_tokens(ts, toks, 64);

    // [, 1, ,, 2, ,, 3, ]
    assert(n == 7);

    printf("  [PASS] array\n");
}

// ============================================================================
// Test 7: Whitespace handling
// ============================================================================

static void
test_whitespace(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_json("  {  }  ");
    int n = drain_tokens(ts, toks, 64);

    assert(n == 2);  // { and }

    printf("  [PASS] whitespace\n");
}

// ============================================================================
// Test 8: Empty input
// ============================================================================

static void
test_empty(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_json("");
    int n = drain_tokens(ts, toks, 64);

    assert(n == 0);

    printf("  [PASS] empty\n");
}

// ============================================================================
// Test 9: Nested structure
// ============================================================================

static void
test_nested(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_json("{\"a\": [1, true, null]}");
    int n = drain_tokens(ts, toks, 64);

    // {, "a", :, [, 1, ,, true, ,, null, ], }
    assert(n == 11);

    printf("  [PASS] nested\n");
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
    printf("Running JSON tokenizer tests...\n");

    test_structural();
    test_strings();
    test_numbers();
    test_keywords();
    test_object();
    test_array();
    test_whitespace();
    test_empty();
    test_nested();

    printf("All JSON tokenizer tests passed.\n");
    n00b_shutdown();
    return 0;
}

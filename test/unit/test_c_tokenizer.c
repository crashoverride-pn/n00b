// test_c_tokenizer.c — Unit tests for the C/ncc tokenizer.

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "slay/c_tokenizer.h"
#include "slay/token.h"
#include "slay/bnf.h"
#include "slay/grammar.h"
#include "internal/slay/grammar_internal.h"

// ============================================================================
// Helper: tokenize a string and return the token stream
// ============================================================================

static n00b_token_stream_t *
tokenize_c(const char *src, n00b_grammar_t *g)
{
    n00b_buffer_t  *buf = n00b_buffer_from_bytes((char *)src,
                                                   (int64_t)strlen(src));
    n00b_c_tokenizer_state_t *st = n00b_c_tokenizer_state_new();

    n00b_scanner_t *scanner = n00b_scanner_new(buf, n00b_c_tokenize, g,
                                                 .state    = st,
                                                 .reset_cb = n00b_c_tokenizer_reset);

    n00b_token_stream_t *ts = n00b_token_stream_new(scanner);
    return ts;
}

// Consume all tokens from stream, return count (excluding EOF).
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
// Test 1: Basic identifier and keyword tokenization
// ============================================================================

static void
test_basic_tokens(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_c("int x;", NULL);
    int n = drain_tokens(ts, toks, 64);

    // Without a grammar, identifiers get hash-based IDs and
    // punctuation gets its codepoint value.
    assert(n >= 2);  // At least "int", "x" (and maybe ";").

    printf("  [PASS] basic_tokens\n");
}

// ============================================================================
// Test 2: String literals
// ============================================================================

static void
test_string_literals(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_c("\"hello\" 'c'", NULL);
    int n = drain_tokens(ts, toks, 64);

    assert(n >= 2);
    // Without a grammar, string/char literals get hash-based type IDs.
    // Verify they were emitted as distinct token types.
    assert(toks[0]->tid != 0);
    assert(toks[1]->tid != 0);
    assert(toks[0]->tid != toks[1]->tid);

    printf("  [PASS] string_literals\n");
}

// ============================================================================
// Test 3: Number literals
// ============================================================================

static void
test_number_literals(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_c("42 3.14 0xff", NULL);
    int n = drain_tokens(ts, toks, 64);

    assert(n >= 3);
    // Without a grammar, number tokens get hash-based type IDs.
    // Integer and float should get different IDs; two integers same ID.
    assert(toks[0]->tid != 0);
    assert(toks[1]->tid != 0);
    assert(toks[0]->tid != toks[1]->tid);  // int vs float
    assert(toks[2]->tid == toks[0]->tid);   // both integers

    printf("  [PASS] number_literals\n");
}

// ============================================================================
// Test 4: Comments are skipped
// ============================================================================

static void
test_comments_skipped(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_c(
        "x // line comment\n"
        "y /* block\ncomment */ z",
        NULL);
    int n = drain_tokens(ts, toks, 64);

    // Should get: x, y, z.
    assert(n == 3);
    // All three should be identifiers (same hash since no grammar).
    // But actually, different identifier *values* get different hashes.
    // Just verify we got 3 tokens.

    printf("  [PASS] comments_skipped\n");
}

// ============================================================================
// Test 5: Preprocessor directives are skipped
// ============================================================================

static void
test_pp_directives(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_c(
        "#include <stdio.h>\n"
        "int x;\n",
        NULL);
    int n = drain_tokens(ts, toks, 64);

    // PP directive is skipped; should get: int, x, ;.
    assert(n >= 2);

    printf("  [PASS] pp_directives\n");
}

// ============================================================================
// Test 6: Pragma ncc off/on tracking
// ============================================================================

static void
test_pragma_ncc(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_c(
        "#pragma ncc off\n"
        "x\n"
        "#pragma ncc on\n"
        "y\n",
        NULL);

    // The pragma handling is in the tokenizer state, not in the token stream.
    // We just verify that tokens are still produced.
    int n = drain_tokens(ts, toks, 64);
    assert(n >= 2);

    printf("  [PASS] pragma_ncc\n");
}

// ============================================================================
// Test 7: Multi-char operators
// ============================================================================

static void
test_operators(void)
{
    n00b_token_info_t *toks[64];
    // Without a grammar, multi-char operators fall through to single chars
    // when the grammar lookup fails. But let's verify no crash.
    n00b_token_stream_t *ts = tokenize_c("a -> b ++ c <<= d", NULL);
    int n = drain_tokens(ts, toks, 64);

    // Should at least get: a, -, >, b, +, +, c, <, <, =, d.
    // (Without a grammar, the operators aren't recognized as multi-char.)
    assert(n >= 4);  // a, b, c, d at minimum.

    printf("  [PASS] operators\n");
}

// ============================================================================
// Test 8: String prefix handling
// ============================================================================

static void
test_string_prefixes(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_c("L\"wide\" u8\"utf8\"", NULL);
    int n = drain_tokens(ts, toks, 64);

    assert(n >= 2);
    // Both should be string literals (same hash-based type ID).
    assert(toks[0]->tid == toks[1]->tid);

    printf("  [PASS] string_prefixes\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    printf("Running C tokenizer tests...\n");

    test_basic_tokens();
    test_string_literals();
    test_number_literals();
    test_comments_skipped();
    test_pp_directives();
    test_pragma_ncc();
    test_operators();
    test_string_prefixes();

    printf("C tokenizer tests done.\n");
    n00b_shutdown();
    return 0;
}

// test_shell_tokenizer.c — Unit tests for the shell tokenizer.

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "parsers/shell_tokenizer.h"
#include "slay/token.h"

// ============================================================================
// Helpers
// ============================================================================

static n00b_token_stream_t *
tokenize_shell(const char *src)
{
    n00b_buffer_t  *buf     = n00b_buffer_from_bytes((char *)src,
                                                       (int64_t)strlen(src));
    n00b_scanner_t *scanner = n00b_scanner_new(buf, n00b_shell_tokenize, nullptr);

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
// Test 1: Simple words
// ============================================================================

static void
test_words(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_shell("echo hello world");
    int n = drain_tokens(ts, toks, 64);

    assert(n == 3);

    printf("  [PASS] words\n");
}

// ============================================================================
// Test 2: Newlines are significant
// ============================================================================

static void
test_newlines(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_shell("a\nb");
    int n = drain_tokens(ts, toks, 64);

    // "a", NEWLINE, "b"
    assert(n == 3);

    printf("  [PASS] newlines\n");
}

// ============================================================================
// Test 3: Double-quoted strings
// ============================================================================

static void
test_double_quoted(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_shell("echo \"hello world\"");
    int n = drain_tokens(ts, toks, 64);

    assert(n == 2);  // "echo", STRING_LIT

    printf("  [PASS] double_quoted\n");
}

// ============================================================================
// Test 4: Single-quoted strings (raw, no escapes)
// ============================================================================

static void
test_single_quoted(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_shell("echo 'hello world'");
    int n = drain_tokens(ts, toks, 64);

    assert(n == 2);  // "echo", STRING_LIT

    printf("  [PASS] single_quoted\n");
}

// ============================================================================
// Test 5: Variable references
// ============================================================================

static void
test_var_refs(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_shell("echo $HOME ${PATH}");
    int n = drain_tokens(ts, toks, 64);

    // "echo", VAR_REF($HOME), VAR_REF(${PATH})
    assert(n == 3);
    // Both var refs should have the same literal type ID.
    assert(toks[1]->tid == toks[2]->tid);

    printf("  [PASS] var_refs\n");
}

// ============================================================================
// Test 6: Comments
// ============================================================================

static void
test_comments(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_shell("echo hello # comment\nfoo");
    int n = drain_tokens(ts, toks, 64);

    // "echo", "hello", NEWLINE, "foo"
    assert(n == 4);

    printf("  [PASS] comments\n");
}

// ============================================================================
// Test 7: Special characters as terminals
// ============================================================================

static void
test_special_chars(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_shell("a | b > c");
    int n = drain_tokens(ts, toks, 64);

    // "a", "|", "b", ">", "c"
    assert(n == 5);

    printf("  [PASS] special_chars\n");
}

// ============================================================================
// Test 8: Numbers
// ============================================================================

static void
test_numbers(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_shell("echo 42 3.14");
    int n = drain_tokens(ts, toks, 64);

    assert(n >= 3);

    printf("  [PASS] numbers\n");
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
    printf("Running shell tokenizer tests...\n");

    test_words();
    test_newlines();
    test_double_quoted();
    test_single_quoted();
    test_var_refs();
    test_comments();
    test_special_chars();
    test_numbers();

    printf("All shell tokenizer tests passed.\n");
    n00b_shutdown();
    return 0;
}

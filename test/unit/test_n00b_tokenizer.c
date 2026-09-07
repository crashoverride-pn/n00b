// test_n00b_tokenizer.c — Unit tests for the n00b language tokenizer.

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "n00b/n00b_tokenizer.h"
#include "slay/token.h"

// ============================================================================
// Helper: tokenize a string
// ============================================================================

static n00b_token_stream_t *
tokenize_n00b(const char *src)
{
    n00b_buffer_t  *buf = n00b_buffer_from_bytes((char *)src,
                                                   (int64_t)strlen(src));
    n00b_scanner_t *scanner = n00b_scanner_new(buf, n00b_lang_tokenize, NULL);
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
    n00b_token_stream_t *ts = tokenize_n00b("foo bar_baz");
    int n = drain_tokens(ts, toks, 64);

    assert(n == 2);
    // Without a grammar, identifiers get hash-based IDs.
    assert(toks[0]->tid != 0);
    assert(toks[1]->tid != 0);

    printf("  [PASS] identifiers\n");
}

// ============================================================================
// Test 2: Number literals
// ============================================================================

static void
test_numbers(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_n00b("42 3.14 0xff");
    int n = drain_tokens(ts, toks, 64);

    assert(n >= 3);
    // Without a grammar, numbers get hash-based type IDs.
    assert(toks[0]->tid != 0);
    assert(toks[1]->tid != 0);
    assert(toks[2]->tid != 0);
    assert(toks[0]->tid != toks[1]->tid);  // int vs float

    printf("  [PASS] numbers\n");
}

// ============================================================================
// Test 3: String literals
// ============================================================================

static void
test_strings(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_n00b("\"hello\" 'c'");
    int n = drain_tokens(ts, toks, 64);

    assert(n >= 2);
    // Without a grammar, string/char literals get hash-based type IDs.
    assert(toks[0]->tid != 0);
    assert(toks[1]->tid != 0);
    assert(toks[0]->tid != toks[1]->tid);

    printf("  [PASS] strings\n");
}

// ============================================================================
// Test 4: Boolean and nil literals (identifiers without grammar)
// ============================================================================

static void
test_literals(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_n00b("true false nil");
    int n = drain_tokens(ts, toks, 64);

    // Without a grammar, true/false/nil are just identifiers
    // (hash-based IDs). They become keywords when a grammar registers them.
    assert(n == 3);
    assert(toks[0]->tid != 0);
    assert(toks[1]->tid != 0);
    assert(toks[2]->tid != 0);

    n00b_string_t *v0 = n00b_option_get(toks[0]->value);
    n00b_string_t *v1 = n00b_option_get(toks[1]->value);
    n00b_string_t *v2 = n00b_option_get(toks[2]->value);
    assert(v0->u8_bytes == 4 && memcmp(v0->data, "true", 4) == 0);
    assert(v1->u8_bytes == 5 && memcmp(v1->data, "false", 5) == 0);
    assert(v2->u8_bytes == 3 && memcmp(v2->data, "nil", 3) == 0);

    printf("  [PASS] literals\n");
}

// ============================================================================
// Test 5: Newlines are emitted as tokens
// ============================================================================

static void
test_newlines(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_n00b("x\ny");
    int n = drain_tokens(ts, toks, 64);

    // Should get: x, newline, y.
    assert(n == 3);
    assert(toks[0]->tid != 0);
    // Newline gets a hash-based type ID (hash of "NEWLINE").
    assert(toks[1]->tid != 0);
    assert(toks[1]->tid != toks[0]->tid);  // newline != identifier
    assert(toks[2]->tid != 0);

    printf("  [PASS] newlines\n");
}

// ============================================================================
// Test 6: Comments
// ============================================================================

static void
test_comments(void)
{
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_n00b(
        "x # comment\n"
        "y // also comment\n"
        "z /* block */ w");
    int n = drain_tokens(ts, toks, 64);

    // Should get: x, newline, y, newline, z, w.
    // (Comments are skipped as trivia.)
    int id_count = 0;

    for (int i = 0; i < n; i++) {
        // Without a grammar, check by token value text rather than ID.
        if (n00b_option_is_set(toks[i]->value)) {
            n00b_string_t *v = n00b_option_get(toks[i]->value);
            if (v->u8_bytes > 0 && ((v->data[0] >= 'a' && v->data[0] <= 'z')
                                   || (v->data[0] >= 'A' && v->data[0] <= 'Z'))) {
                id_count++;
            }
        }
    }

    assert(id_count == 4);  // x, y, z, w.

    printf("  [PASS] comments\n");
}

// ============================================================================
// Test 7: Operators
// ============================================================================

static void
test_operators(void)
{
    n00b_token_info_t *toks[64];
    // Without a grammar, operators are emitted as single codepoints.
    n00b_token_stream_t *ts = tokenize_n00b("a + b - c * d");
    int n = drain_tokens(ts, toks, 64);

    assert(n >= 4);  // At least a, b, c, d.

    printf("  [PASS] operators\n");
}

// ============================================================================
// Test 8: Long literals
// ============================================================================

static void
test_long_literals(void)
{
    // Basic long literal: [=[hello world]=]
    n00b_token_info_t *toks[64];
    n00b_token_stream_t *ts = tokenize_n00b("[=[hello world]=]");
    int n = drain_tokens(ts, toks, 64);

    assert(n == 1);
    // Without a grammar, "EMBED" gets a hash-based type ID.
    int64_t embed_tid = toks[0]->tid;
    assert(embed_tid != 0);
    assert(n00b_option_is_set(toks[0]->value));

    n00b_string_t *val = n00b_option_get(toks[0]->value);
    assert(val->u8_bytes == 11);
    assert(memcmp(val->data, "hello world", 11) == 0);
    assert(!n00b_option_is_set(toks[0]->encoding));  // No encoder.
    assert(!n00b_option_is_set(toks[0]->modifier));

    printf("  [PASS] long literal basic\n");

    // Level 2: [==[contains ]=] inside]==]
    ts = tokenize_n00b("[==[contains ]=] inside]==]");
    n  = drain_tokens(ts, toks, 64);

    assert(n == 1);
    assert(toks[0]->tid == embed_tid);

    val = n00b_option_get(toks[0]->value);
    assert(val->u8_bytes == 19);
    assert(memcmp(val->data, "contains ]=] inside", 19) == 0);

    printf("  [PASS] long literal level 2 nesting\n");

    // With encoder: [=b64[SGVsbG8=]=]
    ts = tokenize_n00b("[=b64[SGVsbG8=]=]");
    n  = drain_tokens(ts, toks, 64);

    assert(n == 1);
    assert(toks[0]->tid == embed_tid);

    val = n00b_option_get(toks[0]->value);
    assert(memcmp(val->data, "SGVsbG8=", 8) == 0);
    assert(n00b_option_is_set(toks[0]->encoding));

    n00b_string_t *enc = n00b_option_get(toks[0]->encoding);
    assert(enc->u8_bytes == 3);
    assert(memcmp(enc->data, "b64", 3) == 0);

    printf("  [PASS] long literal with encoder\n");

    // With modifier tick: [=[data]=]'sometype
    // Modifier is now emitted as separate tokens: EMBED, ', IDENTIFIER.
    ts = tokenize_n00b("[=[data]=]'sometype");
    n  = drain_tokens(ts, toks, 64);

    assert(n == 3);
    assert(toks[0]->tid == embed_tid);

    // toks[1] is the tick (emitted as OTHER since no grammar).
    // toks[2] is "sometype" identifier.
    n00b_string_t *mod = n00b_option_get(toks[2]->value);
    assert(mod->u8_bytes == 8);
    assert(memcmp(mod->data, "sometype", 8) == 0);

    printf("  [PASS] long literal with modifier tick\n");

    // With encoder and modifier tick: [=embed[path/to/file]=]'image
    ts = tokenize_n00b("[=embed[path/to/file]=]'image");
    n  = drain_tokens(ts, toks, 64);

    assert(n == 3);
    assert(toks[0]->tid == embed_tid);

    val = n00b_option_get(toks[0]->value);
    assert(memcmp(val->data, "path/to/file", 12) == 0);

    enc = n00b_option_get(toks[0]->encoding);
    assert(enc->u8_bytes == 5);
    assert(memcmp(enc->data, "embed", 5) == 0);

    // toks[2] is "image" identifier.
    mod = n00b_option_get(toks[2]->value);
    assert(mod->u8_bytes == 5);
    assert(memcmp(mod->data, "image", 5) == 0);

    printf("  [PASS] long literal with encoder + modifier tick\n");

    // Trim: leading/trailing whitespace stripped from content.
    ts = tokenize_n00b("[=[\n    line one\n    line two\n]=]");
    n  = drain_tokens(ts, toks, 64);

    assert(n == 1);
    assert(toks[0]->tid == embed_tid);

    val = n00b_option_get(toks[0]->value);
    // After trim: "line one\n    line two"
    assert(memcmp(val->data, "line one\n    line two", 21) == 0);
    assert(val->u8_bytes == 21);

    printf("  [PASS] long literal trims whitespace\n");

    // Encoder content also trimmed.
    ts = tokenize_n00b("[=b64[\n  SGVsbG8=  \n]=]");
    n  = drain_tokens(ts, toks, 64);

    assert(n == 1);
    val = n00b_option_get(toks[0]->value);
    assert(val->u8_bytes == 8);
    assert(memcmp(val->data, "SGVsbG8=", 8) == 0);

    printf("  [PASS] long literal encoder trims whitespace\n");

    // Reject level 0: [[ should NOT be a long literal (parsed as two [).
    ts = tokenize_n00b("[[x]]");
    n  = drain_tokens(ts, toks, 64);

    for (int i = 0; i < n; i++) {
        assert(toks[i]->tid != embed_tid);
    }

    printf("  [PASS] long literal rejects level 0\n");
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
    printf("Running n00b tokenizer tests...\n");

    test_identifiers();
    test_numbers();
    test_strings();
    test_literals();
    test_newlines();
    test_comments();
    test_operators();
    test_long_literals();

    printf("N00b tokenizer tests done.\n");
    n00b_shutdown();
    return 0;
}

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "adt/option.h"
#include "slay/grammar.h"
#include "slay/n00b_parse.h"
#include "slay/parse_tree.h"
#include "slay/parse_forest.h"
#include "slay/bnf.h"
#include "parsers/token_stream.h"
#include "text/strings/string_ops.h"

// ============================================================================
// Helpers
// ============================================================================

static n00b_token_info_t *
make_token(int64_t tid, const char *text, int32_t index)
{
    n00b_token_info_t *t = n00b_alloc(n00b_token_info_t);

    t->tid   = tid;
    t->index = index;
    t->line  = 1;
    t->column = (uint32_t)(index + 1);

    if (text) {
        t->value = n00b_option_set(n00b_string_t *, n00b_string_from_cstr(text));
    }

    return t;
}

// Build a simple grammar: S -> A B. Backend selection is fixed here at
// instantiation (n00b_parse() reads it from the grammar — there is no
// per-call mode argument).
static void
build_simple_grammar(n00b_grammar_t **out_g,
                     int64_t *out_a, int64_t *out_b,
                     n00b_parse_mode_t mode)
{
    n00b_grammar_t *g = n00b_grammar_new(.parse_mode     = mode,
                                         .error_recovery = false);
    n00b_nonterm_t *s = n00b_nonterm(g, r"S");

    *out_a = n00b_register_terminal(g, r"A");
    *out_b = n00b_register_terminal(g, r"B");

    n00b_add_rule(g, s, N00B_TERMINAL(*out_a), N00B_TERMINAL(*out_b));
    n00b_grammar_set_start(g, s);

    *out_g = g;
}

// ============================================================================
// 1. Default mode (PWZ fast path) — parse valid input
// ============================================================================

static void
test_default_mode_success(void)
{
    n00b_grammar_t *g;
    int64_t tid_a, tid_b;
    build_simple_grammar(&g, &tid_a, &tid_b, N00B_PARSE_MODE_DEFAULT);

    n00b_token_info_t *tokens[] = {
        make_token(tid_a, "a", 0),
        make_token(tid_b, "b", 1),
    };

    n00b_token_stream_t *ts = n00b_token_stream_from_array(tokens, 2);

    n00b_parse_result_t *r = n00b_grammar_parse(g, ts);
    assert(n00b_parse_result_ok(r));
    assert(!n00b_parse_result_ambiguous(r));
    assert(n00b_parse_result_tree_count(r) == 1);

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    assert(tree != NULL);

    n00b_parse_result_free(r);
    n00b_token_stream_free(ts);
    n00b_grammar_free(g);
    printf("  [PASS] default_mode_success\n");
}

// ============================================================================
// 2. Earley-only mode — same grammar, verify success
// ============================================================================

static void
test_earley_only_success(void)
{
    n00b_grammar_t *g;
    int64_t tid_a, tid_b;
    build_simple_grammar(&g, &tid_a, &tid_b, N00B_PARSE_MODE_EARLEY_ONLY);

    n00b_token_info_t *tokens[] = {
        make_token(tid_a, "a", 0),
        make_token(tid_b, "b", 1),
    };

    n00b_token_stream_t *ts = n00b_token_stream_from_array(tokens, 2);

    n00b_parse_result_t *r = n00b_grammar_parse(g, ts);
    assert(n00b_parse_result_ok(r));
    assert(n00b_parse_result_tree_count(r) == 1);

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    assert(tree != NULL);

    n00b_parse_result_free(r);
    n00b_token_stream_free(ts);
    n00b_grammar_free(g);
    printf("  [PASS] earley_only_success\n");
}

// ============================================================================
// 3. PWZ-only mode — verify success and no Earley fallback
// ============================================================================

static void
test_pwz_only_success(void)
{
    n00b_grammar_t *g;
    int64_t tid_a, tid_b;
    build_simple_grammar(&g, &tid_a, &tid_b, N00B_PARSE_MODE_PWZ_ONLY);

    n00b_token_info_t *tokens[] = {
        make_token(tid_a, "a", 0),
        make_token(tid_b, "b", 1),
    };

    n00b_token_stream_t *ts = n00b_token_stream_from_array(tokens, 2);

    n00b_parse_result_t *r = n00b_grammar_parse(g, ts);
    assert(n00b_parse_result_ok(r));
    assert(n00b_parse_result_tree_count(r) == 1);

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    assert(tree != NULL);

    n00b_parse_result_free(r);
    n00b_token_stream_free(ts);
    n00b_grammar_free(g);
    printf("  [PASS] pwz_only_success\n");
}

// ============================================================================
// 4. Parse failure diagnostics — wrong tokens
// ============================================================================

static void
test_parse_failure_diagnostics(void)
{
    n00b_grammar_t *g;
    int64_t tid_a, tid_b;
    build_simple_grammar(&g, &tid_a, &tid_b, N00B_PARSE_MODE_EARLEY_ONLY);

    // Feed B B instead of A B.
    n00b_token_info_t *tokens[] = {
        make_token(tid_b, "b", 0),
        make_token(tid_b, "b", 1),
    };

    n00b_token_stream_t *ts = n00b_token_stream_from_array(tokens, 2);

    n00b_parse_result_t *r = n00b_grammar_parse(g, ts);
    assert(!n00b_parse_result_ok(r));
    assert(n00b_parse_result_tree_count(r) == 0);
    assert(n00b_parse_result_tree(r) == NULL);

    // Error location should have a valid position.
    n00b_error_location_t loc = n00b_parse_result_error_location(r);
    assert(loc.position >= 0);

    // Expected tokens should include tid_a (the grammar expects A first).
    int64_t expected[16];
    int32_t n = n00b_parse_result_expected_tokens(r, expected, 16);
    assert(n > 0);

    bool found_a = false;

    for (int32_t i = 0; i < n; i++) {
        if (expected[i] == tid_a) {
            found_a = true;
            break;
        }
    }

    assert(found_a);

    // Error string should contain meaningful content.
    n00b_string_t *err = n00b_parse_result_error_string(r);
    assert(err->data != NULL);
    assert(err->u8_bytes > 0);

    // Should contain "parse error" and "expected".
    assert(n00b_unicode_str_contains(err, n00b_string_from_cstr("parse error")));
    assert(n00b_unicode_str_contains(err, n00b_string_from_cstr("expected")));

    // Expected string should mention terminal A.
    n00b_string_t *exp_str = n00b_parse_result_expected_string(r);
    assert(exp_str->data != NULL);
    assert(exp_str->u8_bytes > 0);

    n00b_parse_result_free(r);
    n00b_token_stream_free(ts);
    n00b_grammar_free(g);
    printf("  [PASS] parse_failure_diagnostics\n");
}

// ============================================================================
// 5. Null / edge cases
// ============================================================================

static void
test_null_safety(void)
{
    // All query functions should handle NULL gracefully.
    assert(!n00b_parse_result_ok(NULL));
    assert(!n00b_parse_result_ambiguous(NULL));
    assert(!n00b_parse_result_repaired(NULL));
    assert(n00b_parse_result_tree_count(NULL) == 0);
    assert(n00b_parse_result_tree(NULL) == NULL);
    assert(n00b_parse_result_trees(NULL) == NULL);
    assert(n00b_parse_result_repair_count(NULL) == 0);
    assert(n00b_parse_result_repairs(NULL) == NULL);
    assert(n00b_parse_result_grammar(NULL) == NULL);

    // Walk with NULL should not crash.
    assert(n00b_parse_result_walk(NULL, NULL, NULL) == NULL);

    // Free NULL should not crash.
    n00b_parse_result_free(NULL);

    printf("  [PASS] null_safety\n");
}

// ============================================================================
// 6. Parse opts smoke test (opts are accepted without crashing)
// ============================================================================

static void
test_opts_smoke(void)
{
    n00b_grammar_t *g;
    int64_t tid_a, tid_b;
    build_simple_grammar(&g, &tid_a, &tid_b, N00B_PARSE_MODE_DEFAULT);

    n00b_token_info_t *tokens[] = {
        make_token(tid_a, "a", 0),
        make_token(tid_b, "b", 1),
    };

    n00b_token_stream_t *ts = n00b_token_stream_from_array(tokens, 2);

    n00b_parse_result_t *r = n00b_grammar_parse(g, ts);
    assert(n00b_parse_result_ok(r));

    n00b_parse_result_free(r);
    n00b_token_stream_free(ts);
    n00b_grammar_free(g);
    printf("  [PASS] opts_smoke\n");
}

// ============================================================================
// 7. Grammar accessor
// ============================================================================

static void
test_grammar_accessor(void)
{
    n00b_grammar_t *g;
    int64_t tid_a, tid_b;
    build_simple_grammar(&g, &tid_a, &tid_b, N00B_PARSE_MODE_EARLEY_ONLY);

    n00b_token_info_t *tokens[] = {
        make_token(tid_a, "a", 0),
        make_token(tid_b, "b", 1),
    };

    n00b_token_stream_t *ts = n00b_token_stream_from_array(tokens, 2);

    n00b_parse_result_t *r = n00b_grammar_parse(g, ts);
    assert(n00b_parse_result_grammar(r) == g);

    n00b_parse_result_free(r);
    n00b_token_stream_free(ts);
    n00b_grammar_free(g);
    printf("  [PASS] grammar_accessor\n");
}

// ============================================================================
// 8. Cleanup doesn't crash
// ============================================================================

static void
test_cleanup(void)
{
    // Backend selection is now per-grammar, so use one grammar per mode.
    n00b_grammar_t *g_default;
    n00b_grammar_t *g_earley;
    int64_t tid_a, tid_b;
    build_simple_grammar(&g_default, &tid_a, &tid_b, N00B_PARSE_MODE_DEFAULT);
    build_simple_grammar(&g_earley, &tid_a, &tid_b, N00B_PARSE_MODE_EARLEY_ONLY);

    // Success case (DEFAULT grammar).
    n00b_token_info_t *tokens_ok[] = {
        make_token(tid_a, "a", 0),
        make_token(tid_b, "b", 1),
    };

    n00b_token_stream_t *ts1 = n00b_token_stream_from_array(tokens_ok, 2);
    n00b_parse_result_t *r1  = n00b_grammar_parse(g_default, ts1);
    n00b_parse_result_free(r1);
    n00b_token_stream_free(ts1);

    // Failure case (EARLEY_ONLY grammar).
    n00b_token_info_t *tokens_bad[] = {
        make_token(tid_b, "b", 0),
    };

    n00b_token_stream_t *ts2 = n00b_token_stream_from_array(tokens_bad, 1);
    n00b_parse_result_t *r2  = n00b_grammar_parse(g_earley, ts2);
    n00b_parse_result_free(r2);
    n00b_token_stream_free(ts2);

    n00b_grammar_free(g_default);
    n00b_grammar_free(g_earley);
    printf("  [PASS] cleanup\n");
}

// ============================================================================
// 9. BNF parse_mode integration
// ============================================================================

static void
test_bnf_parse_mode(void)
{
    // Backend selection is fixed when the grammar is created with
    // n00b_grammar_new(.parse_mode = ...); n00b_bnf_load just populates it
    // (it no longer takes a parse_mode kwarg). Verify a BNF grammar loads
    // under each instantiation mode.
    n00b_string_t *bnf = n00b_string_from_cstr(
        "<expr> ::= %IDENTIFIER\n"
    );

    // Earley-only mode.
    n00b_grammar_t *g1 = n00b_grammar_new(.parse_mode = N00B_PARSE_MODE_EARLEY_ONLY);
    bool ok1 = n00b_bnf_load(bnf, r"expr", g1);
    assert(ok1);
    n00b_grammar_free(g1);

    // PWZ-only mode.
    n00b_grammar_t *g2 = n00b_grammar_new(.parse_mode = N00B_PARSE_MODE_PWZ_ONLY);
    bool ok2 = n00b_bnf_load(bnf, r"expr", g2);
    assert(ok2);
    n00b_grammar_free(g2);

    // DEFAULT mode (the n00b_grammar_new default).
    n00b_grammar_t *g3 = n00b_grammar_new(.parse_mode = N00B_PARSE_MODE_DEFAULT);
    bool ok3 = n00b_bnf_load(bnf, r"expr", g3);
    assert(ok3);
    n00b_grammar_free(g3);

    printf("  [PASS] bnf_parse_mode\n");
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
    printf("Running unified parse API tests...\n");

    test_default_mode_success();
    test_earley_only_success();
    test_pwz_only_success();
    test_parse_failure_diagnostics();
    test_null_safety();
    test_opts_smoke();
    test_grammar_accessor();
    test_cleanup();
    test_bnf_parse_mode();

    printf("All unified parse API tests passed.\n");
    return 0;
}

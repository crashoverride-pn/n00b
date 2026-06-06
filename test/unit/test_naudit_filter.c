/**
 * @file test_naudit_filter.c
 * @brief WP-009 Phase 3 — naudit filter helper smoke.
 *
 * Verifies the naudit-side wrapper end-to-end:
 *   1. The `match` n00b type registers cleanly with extension
 *      methods, and the JIT pipeline accepts filter expressions
 *      that dot-access registered methods (`arg.nt`, `arg.line`).
 *   2. `n00b_naudit_filter_apply` builds a match handle from a
 *      parse-tree node + source text, invokes the JIT'd predicate,
 *      and returns its bool result.
 *
 * Test approach. The naudit engine itself does its own grammar
 * loading per audited file, but Phase 3 only needs to assert the
 * predicate dispatch path is sound; we don't have to drive the
 * full engine. We parse a tiny n00b program against the eval
 * session's already-loaded n00b grammar, walk the parse tree for
 * `func-def` nodes, and apply the predicate against each.
 *
 * Two predicates exercise different accessor paths:
 *   - `r"arg.nt == r\"func-def\""` — string-returning method
 *     dispatch.
 *   - `r"arg.line > 0"` — integer-returning method dispatch.
 *
 * If WP-010 dispatch is wired correctly, both compile and report
 * the expected truth values.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/buffer.h"
#include "n00b/eval.h"
#include "n00b/n00b_tokenizer.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "slay/grammar.h"
#include "slay/n00b_parse.h"
#include "slay/parse_tree.h"
#include "naudit/filter.h"

// ============================================================================
// Helpers
// ============================================================================

/**
 * Parse n00b source and return the resulting parse tree (NULL on
 * parse error). The eval session's grammar is reused.
 */
static n00b_parse_tree_t *
parse_n00b_source(n00b_grammar_t *g, const char *src)
{
    n00b_buffer_t *buf = n00b_buffer_from_bytes((char *)src,
                                                (int64_t)strlen(src));

    n00b_scanner_t      *scanner = n00b_scanner_new(buf,
                                                    n00b_lang_tokenize, g);
    n00b_token_stream_t *ts      = n00b_token_stream_new(scanner);

    n00b_parse_result_t *r = n00b_grammar_parse(g, ts);

    if (!n00b_parse_result_ok(r)) {
        n00b_string_t *err = n00b_parse_result_error_string(r);
        fprintf(stderr,
                "parse failed: %.*s\n",
                err ? (int)err->u8_bytes : 0,
                err ? err->data : "");
        return nullptr;
    }

    return n00b_parse_result_tree(r);
}

/**
 * DFS the tree collecting all `func-def` nodes (matches the REPL's
 * helper of the same flavour, see src/tools/n00b_repl.c).
 */
static int
collect_func_defs(n00b_parse_tree_t  *node,
                  n00b_parse_tree_t **out,
                  int                 max,
                  int                 count)
{
    if (!node || count >= max) {
        return count;
    }

    if (!n00b_pt_is_token(node) && n00b_pt_is_nt(node, "func-def")) {
        out[count++] = node;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc && count < max; i++) {
        count = collect_func_defs(n00b_pt_get_child(node, i),
                                  out, max, count);
    }

    return count;
}

// ============================================================================
// Cases
// ============================================================================

static void
test_match_type_registration(void)
{
    // Register the type. Subsequent calls are no-ops, so calling
    // twice should be safe.
    n00b_naudit_match_type_register();
    n00b_naudit_match_type_register();

    printf("  [PASS] match_type_registration (idempotent)\n");
}

static void
test_filter_nt_eq_func_def(n00b_eval_session_t *s,
                           n00b_parse_tree_t  **matches,
                           int                  n_matches,
                           n00b_string_t       *src_text)
{
    // The expression text is plain n00b source; n00b does not have a
    // C-style `r"..."` raw-string prefix — string literals are just
    // double-quoted. (The `r"..."` notation in this C test file is the
    // libn00b r-string compile-time macro, which evaluates to a real
    // `n00b_string_t *`.)
    auto r = n00b_naudit_filter_compile(s,
                                        r"unit_test_nt_filter",
                                        r"arg.nt == \"func-def\"");

    if (n00b_result_is_err(r)) {
        n00b_eval_err_t e = (n00b_eval_err_t)n00b_result_get_err(r);
        fprintf(stderr,
                "  [FAIL] compile arg.nt filter: code=%d (%.*s)\n",
                (int)e,
                (int)n00b_eval_err_str(e)->u8_bytes,
                n00b_eval_err_str(e)->data);
    }
    assert(n00b_result_is_ok(r));

    n00b_eval_predicate_fn_t fn = n00b_result_get(r);
    assert(fn);

    int truthy = 0;
    for (int i = 0; i < n_matches; i++) {
        if (n00b_naudit_filter_apply(fn, matches[i], src_text)) {
            truthy++;
        }
    }

    assert(truthy == n_matches);

    printf("  [PASS] filter_nt_eq_func_def "
           "(n=%d, all matched arg.nt == \"func-def\")\n",
           n_matches);
}

static void
test_filter_line_positive(n00b_eval_session_t *s,
                          n00b_parse_tree_t  **matches,
                          int                  n_matches,
                          n00b_string_t       *src_text)
{
    auto r = n00b_naudit_filter_compile(s,
                                        r"unit_test_line_filter",
                                        r"arg.line > 0");

    if (n00b_result_is_err(r)) {
        n00b_eval_err_t e = (n00b_eval_err_t)n00b_result_get_err(r);
        fprintf(stderr,
                "  [FAIL] compile arg.line filter: code=%d (%.*s)\n",
                (int)e,
                (int)n00b_eval_err_str(e)->u8_bytes,
                n00b_eval_err_str(e)->data);
    }
    assert(n00b_result_is_ok(r));

    n00b_eval_predicate_fn_t fn = n00b_result_get(r);
    assert(fn);

    int truthy = 0;
    for (int i = 0; i < n_matches; i++) {
        if (n00b_naudit_filter_apply(fn, matches[i], src_text)) {
            truthy++;
        }
    }

    // Every parsed match has a positive 1-based source line.
    assert(truthy == n_matches);

    printf("  [PASS] filter_line_positive "
           "(n=%d, all matched arg.line > 0)\n",
           n_matches);
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    test_match_type_registration();

    // Open a filter session — registers the match type + installs
    // accessor FFI bindings.
    auto sr = n00b_naudit_filter_session_new();

    if (n00b_result_is_err(sr)) {
        n00b_eval_err_t e = (n00b_eval_err_t)n00b_result_get_err(sr);
        fprintf(stderr,
                "  [FAIL] session_new: code=%d (%.*s)\n",
                (int)e,
                (int)n00b_eval_err_str(e)->u8_bytes,
                n00b_eval_err_str(e)->data);
        return 2;
    }

    n00b_eval_session_t *s = n00b_result_get(sr);
    assert(s);

    // Parse a tiny n00b program containing two func-defs.
    const char *src =
        "func helper(x: int) -> int { return x + 1 }\n"
        "func entry() -> int { return helper(2) }\n";

    n00b_string_t  *src_str = n00b_string_from_cstr(src);
    n00b_grammar_t *g       = n00b_eval_session_grammar(s);

    n00b_parse_tree_t *tree = parse_n00b_source(g, src);
    assert(tree);

    n00b_parse_tree_t *matches[16];
    int n_matches = collect_func_defs(tree, matches, 16, 0);
    assert(n_matches == 2);

    test_filter_nt_eq_func_def(s, matches, n_matches, src_str);
    test_filter_line_positive(s, matches, n_matches, src_str);

    n00b_eval_session_free(s);

    printf("All n00b_naudit_filter smoke tests passed.\n");
    return 0;
}

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "slay/grammar.h"
#include "slay/earley.h"
#include "slay/parse_tree.h"
#include "slay/parse_forest.h"
#include "parsers/token_stream.h"
#include "internal/slay/grammar_internal.h"

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

    if (text) {
        t->value = n00b_option_set(n00b_string_t *, n00b_string_from_cstr(text));
    }

    return t;
}

// Unwrap single-child non-terminal wrappers to reach a token or
// multi-child node.
static n00b_parse_tree_t *
unwrap(n00b_parse_tree_t *t)
{
    while (t && !n00b_tree_is_leaf(t)
           && n00b_tree_num_children(t) == 1) {
        t = n00b_tree_child(t, 0);
    }

    return t;
}

// Get the token id from a (possibly wrapped) child subtree.
static int64_t
child_token_id(n00b_parse_tree_t *parent, size_t index)
{
    n00b_parse_tree_t *child = unwrap(n00b_tree_child(parent, index));

    assert(n00b_tree_is_leaf(child));
    return n00b_tree_leaf_value(child)->tid;
}

// ============================================================================
// 1. Simple sequence: S → A B
// ============================================================================

static void
test_simple_sequence(void)
{
    n00b_grammar_t *g = n00b_grammar_new(.error_recovery = false);
    n00b_nonterm_t *s = n00b_nonterm(g, r"S");

    int64_t tid_a = n00b_register_terminal(g, r"A");
    int64_t tid_b = n00b_register_terminal(g, r"B");

    n00b_add_rule(g, s, N00B_TERMINAL(tid_a), N00B_TERMINAL(tid_b));
    n00b_grammar_set_start(g, s);

    n00b_earley_parser_t *p = n00b_earley_new(g);

    n00b_token_info_t *tokens[] = {
        make_token(tid_a, "a", 0),
        make_token(tid_b, "b", 1),
    };

    n00b_token_stream_t *ts = n00b_token_stream_from_array(tokens, 2);
    bool ok = n00b_earley_parse(p, ts);
    assert(ok);

    n00b_parse_tree_t *tree = n00b_earley_get_tree(p);
    assert(tree != NULL);

    assert(!n00b_tree_is_leaf(tree));
    assert(n00b_tree_num_children(tree) == 2);

    assert(child_token_id(tree, 0) == tid_a);
    assert(child_token_id(tree, 1) == tid_b);

    n00b_earley_free(p);
    n00b_grammar_free(g);
    printf("  [PASS] simple_sequence\n");
}

// ============================================================================
// 2. Alternatives: S → A | B
// ============================================================================

static void
test_alternatives(void)
{
    n00b_grammar_t *g = n00b_grammar_new(.error_recovery = false);
    n00b_nonterm_t *s = n00b_nonterm(g, r"S");

    int64_t tid_a = n00b_register_terminal(g, r"A");
    int64_t tid_b = n00b_register_terminal(g, r"B");

    n00b_add_rule(g, s, N00B_TERMINAL(tid_a));
    n00b_add_rule(g, s, N00B_TERMINAL(tid_b));
    n00b_grammar_set_start(g, s);

    n00b_earley_parser_t *p = n00b_earley_new(g);

    // Parse [A]
    n00b_token_info_t *tokens_a[] = {make_token(tid_a, "a", 0)};
    n00b_token_stream_t *ts_a = n00b_token_stream_from_array(tokens_a, 1);
    assert(n00b_earley_parse(p, ts_a));

    n00b_parse_tree_t *tree_a = n00b_earley_get_tree(p);
    assert(tree_a != NULL);
    assert(n00b_tree_num_children(tree_a) >= 1);
    assert(child_token_id(tree_a, 0) == tid_a);

    // Parse [B]
    n00b_earley_reset(p);
    n00b_token_info_t *tokens_b[] = {make_token(tid_b, "b", 0)};
    n00b_token_stream_t *ts_b = n00b_token_stream_from_array(tokens_b, 1);
    assert(n00b_earley_parse(p, ts_b));

    n00b_parse_tree_t *tree_b = n00b_earley_get_tree(p);
    assert(tree_b != NULL);
    assert(n00b_tree_num_children(tree_b) >= 1);
    assert(child_token_id(tree_b, 0) == tid_b);

    n00b_earley_free(p);
    n00b_grammar_free(g);
    printf("  [PASS] alternatives\n");
}

// ============================================================================
// 3. Left recursion: E → E A | A
// ============================================================================

static void
test_left_recursion(void)
{
    n00b_grammar_t *g = n00b_grammar_new(.error_recovery = false);
    n00b_nonterm_t *e = n00b_nonterm(g, r"E");

    int64_t tid_a = n00b_register_terminal(g, r"A");

    n00b_add_rule(g, e, N00B_NT(e), N00B_TERMINAL(tid_a));
    n00b_add_rule(g, e, N00B_TERMINAL(tid_a));
    n00b_grammar_set_start(g, e);

    n00b_earley_parser_t *p = n00b_earley_new(g);

    n00b_token_info_t *tokens[] = {
        make_token(tid_a, "a", 0),
        make_token(tid_a, "a", 1),
        make_token(tid_a, "a", 2),
    };

    n00b_token_stream_t *ts = n00b_token_stream_from_array(tokens, 3);
    bool ok = n00b_earley_parse(p, ts);
    assert(ok);

    n00b_parse_tree_t *tree = n00b_earley_get_tree(p);
    assert(tree != NULL);

    n00b_nt_node_t *root_pn = &n00b_tree_node_value(tree);
    assert(!n00b_tree_is_leaf(tree));
    assert(root_pn->end - root_pn->start == 3);

    n00b_earley_free(p);
    n00b_grammar_free(g);
    printf("  [PASS] left_recursion\n");
}

// ============================================================================
// 4. Right recursion: E → A E | A  (exercises Leo optimization)
// ============================================================================

static void
test_right_recursion(void)
{
    n00b_grammar_t *g = n00b_grammar_new(.error_recovery = false);
    n00b_nonterm_t *e = n00b_nonterm(g, r"E");

    int64_t tid_a = n00b_register_terminal(g, r"A");

    n00b_add_rule(g, e, N00B_TERMINAL(tid_a), N00B_NT(e));
    n00b_add_rule(g, e, N00B_TERMINAL(tid_a));
    n00b_grammar_set_start(g, e);

    n00b_earley_parser_t *p = n00b_earley_new(g);

    n00b_token_info_t *tokens[] = {
        make_token(tid_a, "a", 0),
        make_token(tid_a, "a", 1),
        make_token(tid_a, "a", 2),
    };

    n00b_token_stream_t *ts = n00b_token_stream_from_array(tokens, 3);
    bool ok = n00b_earley_parse(p, ts);
    assert(ok);

    n00b_parse_tree_t *tree = n00b_earley_get_tree(p);
    assert(tree != NULL);

    n00b_nt_node_t *root_pn = &n00b_tree_node_value(tree);
    assert(!n00b_tree_is_leaf(tree));
    assert(root_pn->end - root_pn->start == 3);

    n00b_earley_free(p);
    n00b_grammar_free(g);
    printf("  [PASS] right_recursion\n");
}

// ============================================================================
// 5. EBNF star: S → A*
// ============================================================================

static void
test_ebnf_star(void)
{
    n00b_grammar_t *g = n00b_grammar_new(.error_recovery = false);
    n00b_nonterm_t *s = n00b_nonterm(g, r"S");

    int64_t tid_a = n00b_register_terminal(g, r"A");

    n00b_add_rule(g, s, n00b_star(g, N00B_TERMINAL(tid_a)));
    n00b_grammar_set_start(g, s);

    n00b_earley_parser_t *p = n00b_earley_new(g);

    // Parse [A, A]
    n00b_token_info_t *tokens[] = {
        make_token(tid_a, "a", 0),
        make_token(tid_a, "a", 1),
    };

    n00b_token_stream_t *ts = n00b_token_stream_from_array(tokens, 2);
    bool ok = n00b_earley_parse(p, ts);
    assert(ok);

    n00b_parse_tree_t *tree = n00b_earley_get_tree(p);
    assert(tree != NULL);

    n00b_nt_node_t *root_pn = &n00b_tree_node_value(tree);
    assert(root_pn->end - root_pn->start == 2);

    n00b_earley_free(p);
    n00b_grammar_free(g);
    printf("  [PASS] ebnf_star\n");
}

// ============================================================================
// 6. EBNF plus: S → A+
// ============================================================================

static void
test_ebnf_plus(void)
{
    n00b_grammar_t *g = n00b_grammar_new(.error_recovery = false);
    n00b_nonterm_t *s = n00b_nonterm(g, r"S");

    int64_t tid_a = n00b_register_terminal(g, r"A");

    n00b_add_rule(g, s, n00b_plus_group(g, N00B_TERMINAL(tid_a)));
    n00b_grammar_set_start(g, s);

    n00b_earley_parser_t *p = n00b_earley_new(g);

    // Parse [A, A, A]
    n00b_token_info_t *tokens[] = {
        make_token(tid_a, "a", 0),
        make_token(tid_a, "a", 1),
        make_token(tid_a, "a", 2),
    };

    n00b_token_stream_t *ts = n00b_token_stream_from_array(tokens, 3);
    bool ok = n00b_earley_parse(p, ts);
    assert(ok);

    n00b_parse_tree_t *tree = n00b_earley_get_tree(p);
    assert(tree != NULL);

    n00b_nt_node_t *root_pn = &n00b_tree_node_value(tree);
    assert(root_pn->end - root_pn->start == 3);

    n00b_earley_free(p);
    n00b_grammar_free(g);
    printf("  [PASS] ebnf_plus\n");
}

// ============================================================================
// 7. EBNF optional: S → A B?
// ============================================================================

static void
test_ebnf_optional(void)
{
    n00b_grammar_t *g = n00b_grammar_new(.error_recovery = false);
    n00b_nonterm_t *s = n00b_nonterm(g, r"S");

    int64_t tid_a = n00b_register_terminal(g, r"A");
    int64_t tid_b = n00b_register_terminal(g, r"B");

    n00b_add_rule(g, s, N00B_TERMINAL(tid_a), n00b_optional(g, N00B_TERMINAL(tid_b)));
    n00b_grammar_set_start(g, s);

    n00b_earley_parser_t *p = n00b_earley_new(g);

    // Parse [A] — B is optional, should succeed.
    n00b_token_info_t *tokens_a[] = {make_token(tid_a, "a", 0)};
    n00b_token_stream_t *ts_a = n00b_token_stream_from_array(tokens_a, 1);
    assert(n00b_earley_parse(p, ts_a));

    // Parse [A, B] — should also succeed.
    n00b_earley_reset(p);
    n00b_token_info_t *tokens_ab[] = {
        make_token(tid_a, "a", 0),
        make_token(tid_b, "b", 1),
    };
    n00b_token_stream_t *ts_ab = n00b_token_stream_from_array(tokens_ab, 2);
    assert(n00b_earley_parse(p, ts_ab));

    n00b_earley_free(p);
    n00b_grammar_free(g);
    printf("  [PASS] ebnf_optional\n");
}

// ============================================================================
// 8. Parse failure: input doesn't match grammar
// ============================================================================

static void
test_parse_failure(void)
{
    n00b_grammar_t *g = n00b_grammar_new(.error_recovery = false);
    n00b_nonterm_t *s = n00b_nonterm(g, r"S");

    int64_t tid_a = n00b_register_terminal(g, r"A");
    int64_t tid_b = n00b_register_terminal(g, r"B");

    n00b_add_rule(g, s, N00B_TERMINAL(tid_a), N00B_TERMINAL(tid_b));
    n00b_grammar_set_start(g, s);

    n00b_earley_parser_t *p = n00b_earley_new(g);

    // Parse [B, A] — wrong order, should fail.
    n00b_token_info_t *tokens[] = {
        make_token(tid_b, "b", 0),
        make_token(tid_a, "a", 1),
    };

    n00b_token_stream_t *ts = n00b_token_stream_from_array(tokens, 2);
    bool ok = n00b_earley_parse(p, ts);
    assert(!ok);

    n00b_earley_free(p);
    n00b_grammar_free(g);
    printf("  [PASS] parse_failure\n");
}

// ============================================================================
// 9. Empty input with epsilon rule: S → ε
// ============================================================================

static void
test_empty_input(void)
{
    n00b_grammar_t *g = n00b_grammar_new(.error_recovery = false);
    n00b_nonterm_t *s = n00b_nonterm(g, r"S");

    n00b_add_rule(g, s, N00B_EPSILON());
    n00b_grammar_set_start(g, s);

    n00b_earley_parser_t *p = n00b_earley_new(g);

    n00b_token_stream_t *ts = n00b_token_stream_from_array(NULL, 0);
    bool ok = n00b_earley_parse(p, ts);
    assert(ok);

    n00b_parse_tree_t *tree = n00b_earley_get_tree(p);
    assert(tree != NULL);

    n00b_earley_free(p);
    n00b_grammar_free(g);
    printf("  [PASS] empty_input\n");
}

// ============================================================================
// 10. Reset and reparse
// ============================================================================

static void
test_reset_reparse(void)
{
    n00b_grammar_t *g = n00b_grammar_new(.error_recovery = false);
    n00b_nonterm_t *s = n00b_nonterm(g, r"S");

    int64_t tid_a = n00b_register_terminal(g, r"A");
    int64_t tid_b = n00b_register_terminal(g, r"B");

    n00b_add_rule(g, s, N00B_TERMINAL(tid_a));
    n00b_add_rule(g, s, N00B_TERMINAL(tid_b));
    n00b_grammar_set_start(g, s);

    n00b_earley_parser_t *p = n00b_earley_new(g);

    // First parse: [A]
    n00b_token_info_t *tokens_a[] = {make_token(tid_a, "a", 0)};
    n00b_token_stream_t *ts_a = n00b_token_stream_from_array(tokens_a, 1);
    assert(n00b_earley_parse(p, ts_a));
    assert(n00b_earley_get_tree(p) != NULL);

    // Reset and parse again: [B]
    n00b_earley_reset(p);
    n00b_token_info_t *tokens_b[] = {make_token(tid_b, "b", 0)};
    n00b_token_stream_t *ts_b = n00b_token_stream_from_array(tokens_b, 1);
    assert(n00b_earley_parse(p, ts_b));

    n00b_parse_tree_t *tree_b = n00b_earley_get_tree(p);
    assert(tree_b != NULL);
    assert(child_token_id(tree_b, 0) == tid_b);

    n00b_earley_free(p);
    n00b_grammar_free(g);
    printf("  [PASS] reset_reparse\n");
}

// ============================================================================
// 11. Multi-rule grammar: expr → term + expr | term, term → NUM
// ============================================================================

static void
test_expression_grammar(void)
{
    n00b_grammar_t *g = n00b_grammar_new(.error_recovery = false);
    n00b_nonterm_t *expr = n00b_nonterm(g, r"expr");
    n00b_nonterm_t *term = n00b_nonterm(g, r"term");

    int64_t tid_num  = n00b_register_terminal(g, r"NUM");
    int64_t tid_plus = n00b_register_terminal(g, r"+");

    n00b_add_rule(g, expr, N00B_NT(term), N00B_TERMINAL(tid_plus), N00B_NT(expr));
    n00b_add_rule(g, expr, N00B_NT(term));

    n00b_add_rule(g, term, N00B_TERMINAL(tid_num));

    n00b_grammar_set_start(g, expr);

    n00b_earley_parser_t *p = n00b_earley_new(g);

    // Parse: NUM + NUM + NUM
    n00b_token_info_t *tokens[] = {
        make_token(tid_num, "1", 0),
        make_token(tid_plus, "+", 1),
        make_token(tid_num, "2", 2),
        make_token(tid_plus, "+", 3),
        make_token(tid_num, "3", 4),
    };

    n00b_token_stream_t *ts = n00b_token_stream_from_array(tokens, 5);
    bool ok = n00b_earley_parse(p, ts);
    assert(ok);

    n00b_parse_tree_t *tree = n00b_earley_get_tree(p);
    assert(tree != NULL);

    n00b_nt_node_t *root_pn = &n00b_tree_node_value(tree);
    assert(!n00b_tree_is_leaf(tree));
    assert(root_pn->start == 0);
    assert(root_pn->end == 5);

    n00b_earley_free(p);
    n00b_grammar_free(g);
    printf("  [PASS] expression_grammar\n");
}

// ============================================================================
// 12. Tree walk with grammar actions
// ============================================================================

typedef struct {
    int node_count;
} walk_state_t;

static void *
count_action(n00b_nt_node_t *node, void *children, void *thunk)
{
    (void)children;
    (void)node;
    walk_state_t *st = (walk_state_t *)thunk;

    // Walk actions are only called for NT nodes.
    st->node_count++;

    return NULL;
}

static void
test_tree_walk(void)
{
    n00b_grammar_t *g = n00b_grammar_new();
    n00b_nonterm_t *s = n00b_nonterm(g, r"S");

    int64_t tid_a = n00b_register_terminal(g, r"A");
    int64_t tid_b = n00b_register_terminal(g, r"B");

    n00b_add_rule(g, s, N00B_TERMINAL(tid_a), N00B_TERMINAL(tid_b));
    n00b_grammar_set_start(g, s);

    n00b_grammar_set_default_action(g, count_action);

    n00b_earley_parser_t *p = n00b_earley_new(g);

    n00b_token_info_t *tokens[] = {
        make_token(tid_a, "a", 0),
        make_token(tid_b, "b", 1),
    };

    n00b_token_stream_t *ts = n00b_token_stream_from_array(tokens, 2);
    assert(n00b_earley_parse(p, ts));

    n00b_parse_tree_t *tree = n00b_earley_get_tree(p);
    assert(tree != NULL);

    walk_state_t st = {0};
    n00b_parse_tree_walk(g, tree, &st);

    // Should have visited at least the root S node.
    assert(st.node_count >= 1);

    n00b_earley_free(p);
    n00b_grammar_free(g);
    printf("  [PASS] tree_walk\n");
}

// ============================================================================
// 13. Parse count — verify recognizer finds completions
// ============================================================================

static void
test_parse_count(void)
{
    n00b_grammar_t *g = n00b_grammar_new(.error_recovery = false);
    n00b_nonterm_t *s = n00b_nonterm(g, r"S");

    int64_t tid_a = n00b_register_terminal(g, r"A");

    n00b_add_rule(g, s, N00B_TERMINAL(tid_a));
    n00b_grammar_set_start(g, s);

    n00b_earley_parser_t *p = n00b_earley_new(g);

    n00b_token_info_t *tokens[] = {make_token(tid_a, "a", 0)};
    n00b_token_stream_t *ts = n00b_token_stream_from_array(tokens, 1);
    assert(n00b_earley_parse(p, ts));

    int32_t count = n00b_earley_parse_count(p);
    assert(count >= 1);

    n00b_earley_free(p);
    n00b_grammar_free(g);
    printf("  [PASS] parse_count\n");
}

// ============================================================================
// 14. Forest extraction — parse forest API
// ============================================================================

static void
test_forest_extraction(void)
{
    n00b_grammar_t *g = n00b_grammar_new();
    n00b_nonterm_t *s = n00b_nonterm(g, r"S");

    int64_t tid_a = n00b_register_terminal(g, r"A");
    int64_t tid_b = n00b_register_terminal(g, r"B");

    n00b_add_rule(g, s, N00B_TERMINAL(tid_a), N00B_TERMINAL(tid_b));
    n00b_grammar_set_start(g, s);

    n00b_earley_parser_t *p = n00b_earley_new(g);

    n00b_token_info_t *tokens[] = {
        make_token(tid_a, "a", 0),
        make_token(tid_b, "b", 1),
    };

    n00b_token_stream_t *ts = n00b_token_stream_from_array(tokens, 2);
    assert(n00b_earley_parse(p, ts));

    n00b_parse_forest_t forest = n00b_earley_get_forest(p);

    assert(n00b_parse_forest_count(&forest) >= 1);
    assert(n00b_parse_forest_best(&forest) != NULL);
    assert(n00b_parse_forest_tree(&forest, 0) != NULL);

    n00b_parse_forest_free(&forest);
    n00b_earley_free(p);
    n00b_grammar_free(g);
    printf("  [PASS] forest_extraction\n");
}

// ============================================================================
// 15. One-shot parse via n00b_earley_parse_grammar
// ============================================================================

static void
test_one_shot_parse(void)
{
    n00b_grammar_t *g = n00b_grammar_new(.error_recovery = false);
    n00b_nonterm_t *s = n00b_nonterm(g, r"S");

    int64_t tid_a = n00b_register_terminal(g, r"A");

    n00b_add_rule(g, s, N00B_TERMINAL(tid_a));
    n00b_grammar_set_start(g, s);

    n00b_token_info_t *tokens[] = {make_token(tid_a, "a", 0)};
    n00b_token_stream_t *ts = n00b_token_stream_from_array(tokens, 1);

    n00b_parse_forest_t forest = n00b_earley_parse_grammar(g, ts);

    assert(n00b_parse_forest_count(&forest) >= 1);

    n00b_parse_tree_t *tree = n00b_parse_forest_best(&forest);
    assert(tree != NULL);

    assert(!n00b_tree_is_leaf(tree));

    n00b_parse_forest_free(&forest);
    n00b_grammar_free(g);
    printf("  [PASS] one_shot_parse\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    setbuf(stdout, NULL);
    printf("Running Earley parser tests...\n");

    test_simple_sequence();
    test_alternatives();
    test_left_recursion();
    test_right_recursion();
    test_ebnf_star();
    test_ebnf_plus();
    test_ebnf_optional();
    test_parse_failure();
    test_empty_input();
    test_reset_reparse();
    test_expression_grammar();
    test_tree_walk();
    test_parse_count();
    test_forest_extraction();
    test_one_shot_parse();

    printf("All Earley parser tests passed.\n");
    n00b_shutdown();
    return 0;
}

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "slay/bnf.h"
#include "slay/pwz.h"
#include "slay/parse_tree.h"
#include "internal/slay/grammar_internal.h"
#include "util/assert.h"

// r"..." is a raw string (no escape processing), so \n stays literal.
// BNF needs actual newlines, so we use n00b_string_from_cstr for BNF text.
static n00b_string_t *
bnf(const char *text)
{
    return n00b_string_from_cstr(text);
}

// ============================================================================
// 1. Simple grammar: S ::= A B
// ============================================================================

static void
test_simple_grammar(void)
{
    n00b_grammar_t *g = n00b_grammar_new();

    bool ok = n00b_bnf_load(
        bnf("<S> ::= %IDENTIFIER %INTEGER\n"),
        r"S", g);

    assert(ok);
    assert(g->finalized);
    assert(g->default_start >= 0);

    n00b_nonterm_t *s = n00b_get_nonterm(g, g->default_start);
    assert(s != NULL);
    assert(n00b_unicode_str_eq(s->name, r"S"));

    n00b_grammar_free(g);
    printf("  [PASS] simple_grammar\n");
}

// ============================================================================
// 2. Alternatives: S ::= A | B
// ============================================================================

static void
test_alternatives(void)
{
    n00b_grammar_t *g = n00b_grammar_new();

    bool ok = n00b_bnf_load(
        bnf("<S> ::= %IDENTIFIER | %INTEGER\n"),
        r"S", g);

    assert(ok);

    n00b_nonterm_t *s = n00b_get_nonterm(g, g->default_start);
    assert(s != NULL);
    // S should have 2 rules (one for each alternative).
    assert(n00b_list_len(s->rule_ids) >= 2);

    n00b_grammar_free(g);
    printf("  [PASS] alternatives\n");
}

// ============================================================================
// 2b. Recursive order preservation
// ============================================================================

static void
assert_terminal(n00b_parse_rule_t *rule, size_t ix, int64_t tid)
{
    n00b_require(n00b_list_len(rule->contents) > ix,
                 "expected rule content at index");
    n00b_require(rule->contents.data[ix].kind == N00B_MATCH_TERMINAL,
                 "expected terminal match");
    n00b_require(rule->contents.data[ix].terminal_id == tid,
                 "unexpected terminal id");
}

static int64_t
literal_type_id(n00b_grammar_t *g, n00b_string_t *name)
{
    bool    found = false;
    int64_t id    = n00b_dict_get(g->literal_type_map, name, &found);

    n00b_require(found, "expected literal type id");
    return id;
}

static n00b_nonterm_t *
lookup_nonterm(n00b_grammar_t *g, n00b_string_t *name)
{
    bool    found = false;
    int64_t id    = n00b_dict_get(g->nt_map, name, &found);

    n00b_require(found, "expected nonterminal");
    return n00b_get_nonterm(g, id);
}

static void
test_recursive_order_preservation(void)
{
    n00b_grammar_t *g = n00b_grammar_new(.error_recovery = false);

    bool ok = n00b_bnf_load(
        bnf("@tokenizer(\"first\")\n"
            "<S> @declares($0, $1, \"pair\") ::= %FIRST %SECOND | %THIRD %FOURTH\n"
            "<T> ::= %FIFTH\n"
            "@tokenizer(\"n00b\")\n"
            "<S> ::= %SIXTH\n"),
        r"S", g);

    n00b_require(ok, "BNF order fixture should load");
    n00b_require(g->tokenizer_name != nullptr,
                 "grammar-level tokenizer annotation missing");
    n00b_require(n00b_unicode_str_eq(g->tokenizer_name, r"n00b"),
                 "unexpected tokenizer annotation value");

    n00b_nonterm_t *s = n00b_get_nonterm(g, g->default_start);
    n00b_require(s != nullptr, "expected default start nonterminal");
    n00b_require(n00b_unicode_str_eq(s->name, r"S"),
                 "unexpected default start name");
    n00b_require(n00b_list_len(s->rule_ids) == 3,
                 "unexpected S rule count");

    int64_t first  = literal_type_id(g, r"FIRST");
    int64_t second = literal_type_id(g, r"SECOND");
    int64_t third  = literal_type_id(g, r"THIRD");
    int64_t fourth = literal_type_id(g, r"FOURTH");
    int64_t fifth  = literal_type_id(g, r"FIFTH");
    int64_t sixth  = literal_type_id(g, r"SIXTH");

    n00b_parse_rule_t *s0 = n00b_get_rule(g, s->rule_ids.data[0]);
    n00b_parse_rule_t *s1 = n00b_get_rule(g, s->rule_ids.data[1]);
    n00b_parse_rule_t *s2 = n00b_get_rule(g, s->rule_ids.data[2]);

    n00b_require(s0 != nullptr, "expected first S rule");
    n00b_require(s1 != nullptr, "expected second S rule");
    n00b_require(s2 != nullptr, "expected third S rule");
    n00b_require(n00b_list_len(s0->contents) == 2,
                 "unexpected first S rule length");
    assert_terminal(s0, 0, first);
    assert_terminal(s0, 1, second);
    n00b_require(n00b_list_len(s1->contents) == 2,
                 "unexpected second S rule length");
    assert_terminal(s1, 0, third);
    assert_terminal(s1, 1, fourth);
    n00b_require(n00b_list_len(s2->contents) == 1,
                 "unexpected third S rule length");
    assert_terminal(s2, 0, sixth);

    n00b_require(n00b_list_len(s0->annotations) == 1,
                 "expected S rule annotation");
    n00b_annotation_t *decl = s0->annotations.data[0];

    n00b_require(decl->kind == N00B_ANNOT_DECLARES,
                 "expected declares annotation");
    n00b_require(decl->name_ref.kind == N00B_ROLE_BY_INDEX,
                 "expected declares name ref by index");
    n00b_require(decl->name_ref.index == 0,
                 "unexpected declares name ref index");
    n00b_require(decl->type_ref.kind == N00B_ROLE_BY_INDEX,
                 "expected declares type ref by index");
    n00b_require(decl->type_ref.index == 1,
                 "unexpected declares type ref index");
    n00b_require(n00b_unicode_str_eq(decl->sym_kind, r"pair"),
                 "unexpected declares symbol kind");

    n00b_nonterm_t *t = lookup_nonterm(g, r"T");
    n00b_require(t != nullptr, "expected T nonterminal");
    n00b_require(n00b_list_len(t->rule_ids) == 1,
                 "unexpected T rule count");

    n00b_parse_rule_t *t0 = n00b_get_rule(g, t->rule_ids.data[0]);

    n00b_require(t0 != nullptr, "expected T rule");
    n00b_require(n00b_list_len(t0->contents) == 1,
                 "unexpected T rule length");
    assert_terminal(t0, 0, fifth);

    n00b_grammar_free(g);
}

// ============================================================================
// 3. Multiple rules with cross-references
// ============================================================================

static void
test_multiple_rules(void)
{
    n00b_grammar_t *g = n00b_grammar_new();

    bool ok = n00b_bnf_load(
        bnf("<expr> ::= <term> | <expr> %IDENTIFIER <term>\n"
            "<term> ::= %INTEGER\n"),
        r"expr", g);

    assert(ok);

    n00b_nonterm_t *expr = n00b_get_nonterm(g, g->default_start);
    assert(expr != NULL);
    assert(n00b_unicode_str_eq(expr->name, r"expr"));

    n00b_grammar_free(g);
    printf("  [PASS] multiple_rules\n");
}

// ============================================================================
// 4. Literal tokens
// ============================================================================

static void
test_literal_tokens(void)
{
    n00b_grammar_t *g = n00b_grammar_new();

    bool ok = n00b_bnf_load(
        bnf("<S> ::= \"hello\" %IDENTIFIER\n"),
        r"S", g);

    assert(ok);
    assert(g->finalized);

    n00b_grammar_free(g);
    printf("  [PASS] literal_tokens\n");
}

// ============================================================================
// 5. Comments and continuation lines
// ============================================================================

static void
test_comments_and_continuations(void)
{
    n00b_grammar_t *g = n00b_grammar_new();

    bool ok = n00b_bnf_load(
        bnf("# This is a comment\n"
            "<S> ::= %IDENTIFIER\n"
            "    | %INTEGER  # another comment\n"),
        r"S", g);

    assert(ok);

    n00b_nonterm_t *s = n00b_get_nonterm(g, g->default_start);
    assert(s != NULL);
    assert(n00b_list_len(s->rule_ids) >= 2);

    n00b_grammar_free(g);
    printf("  [PASS] comments_and_continuations\n");
}

// ============================================================================
// 6. Empty input returns false
// ============================================================================

static void
test_empty_input(void)
{
    n00b_grammar_t *g = n00b_grammar_new();

    bool ok = n00b_bnf_load(bnf(""), r"S", g);
    assert(!ok);

    n00b_grammar_free(g);
    printf("  [PASS] empty_input\n");
}

// ============================================================================
// 7. Null grammar returns false
// ============================================================================

static void
test_null_grammar(void)
{
    bool ok = n00b_bnf_load(
        bnf("<S> ::= %IDENTIFIER\n"), r"S", NULL);
    assert(!ok);
    printf("  [PASS] null_grammar\n");
}

// ============================================================================
// 8. Explicit parse_fn kwarg
// ============================================================================

static void
test_explicit_parse_fn(void)
{
    n00b_grammar_t *g = n00b_grammar_new();

    bool ok = n00b_bnf_load(
        bnf("<S> ::= %IDENTIFIER\n"),
        r"S", g,
        .parse_fn = n00b_pwz_parse_grammar);

    assert(ok);
    assert(g->finalized);

    n00b_grammar_free(g);
    printf("  [PASS] explicit_parse_fn\n");
}

// ============================================================================
// 9. EBNF quantifier: S ::= A+
// ============================================================================

static void
test_ebnf_plus(void)
{
    n00b_grammar_t *g = n00b_grammar_new();

    bool ok = n00b_bnf_load(
        bnf("<S> ::= %IDENTIFIER+\n"),
        r"S", g);

    assert(ok);
    assert(g->finalized);

    n00b_grammar_free(g);
    printf("  [PASS] ebnf_plus\n");
}

// ============================================================================
// 10. Character class: __DIGIT
// ============================================================================

static void
test_char_class(void)
{
    n00b_grammar_t *g = n00b_grammar_new();

    bool ok = n00b_bnf_load(
        bnf("<S> ::= __DIGIT+\n"),
        r"S", g);

    assert(ok);
    assert(g->finalized);

    n00b_grammar_free(g);
    printf("  [PASS] char_class\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("BNF loader tests:\n");
    test_simple_grammar();
    test_alternatives();
    test_recursive_order_preservation();
    test_multiple_rules();
    test_literal_tokens();
    test_comments_and_continuations();
    test_empty_input();
    test_null_grammar();
    test_explicit_parse_fn();
    test_ebnf_plus();
    test_char_class();

    printf("All BNF tests passed.\n");
    return 0;
}

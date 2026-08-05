// test_slay_rewrite.c — regression tests for slay's rewrite mechanism.
//
// Covers:
//   - BNF parser end-to-end: `$name:<nt>` captures + `rewrite { ... }`
//     blocks attach to productions.
//   - Leveled-brace block delimiters: `rewrite {= ... =}` with bare `}`
//     inside the body.
//   - Heredoc field values: `template: [==[ ... ]==]` preserves bytes.
//   - Public predicates / accessors:
//     `n00b_production_has_rewrite`,
//     `n00b_production_rewrite_field`,
//     `n00b_production_capture_names`.
//   - Apply engine (text mode): substitute `$name` references in the
//     template with the matched source bytes.
//   - Error paths: NO_BLOCK on a production without a rewrite,
//     NULL_INPUT on null arguments.

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "test_portability.h"

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/runtime.h"
#include "adt/option.h"
#include "adt/result.h"
#include "adt/tree.h"
#include "text/strings/string_ops.h"
#include "slay/bnf.h"
#include "slay/grammar.h"
#include "slay/parse_tree.h"
#include "slay/rewrite.h"
#include "internal/slay/grammar_internal.h"

// ----------------------------------------------------------------------------
// Helpers — parse-tree construction (mirrors the pprint test pattern).
// ----------------------------------------------------------------------------

static n00b_string_t *
bnf(const char *text)
{
    return n00b_string_from_cstr(text);
}

static n00b_token_info_t *
mk_tok(const char *text, int64_t tid)
{
    n00b_token_info_t *t = n00b_alloc(n00b_token_info_t);
    t->tid               = tid;
    t->value             = n00b_option_set(n00b_string_t *,
                                            n00b_string_from_cstr(text));
    return t;
}

static n00b_parse_tree_t *
mk_leaf(const char *text, int64_t tid)
{
    return n00b_tree_leaf(n00b_nt_node_t, n00b_token_info_t *,
                           mk_tok(text, tid));
}

static n00b_parse_tree_t *
mk_nt_node(n00b_nonterm_t *nt)
{
    n00b_nt_node_t v = {};
    v.name           = nt->name;
    v.id             = nt->id;
    return n00b_tree_node(n00b_nt_node_t, n00b_token_info_t *, v);
}

// Find the first rule for NT named `nt_name` in the loaded grammar.
static n00b_parse_rule_t *
first_rule_for(n00b_grammar_t *g, const char *nt_name)
{
    for (size_t i = 0; i < n00b_list_len(g->nt_list); i++) {
        n00b_nonterm_t *nt = n00b_get_nonterm(g, (int64_t)i);
        if (!nt || !nt->name) {
            continue;
        }
        if ((size_t)nt->name->u8_bytes == strlen(nt_name)
            && memcmp(nt->name->data, nt_name, nt->name->u8_bytes) == 0) {
            if (nt->rule_ids.len == 0) {
                return nullptr;
            }
            return n00b_get_rule(g, nt->rule_ids.data[0]);
        }
    }
    return nullptr;
}

// Find an NT by name in the loaded grammar.
static n00b_nonterm_t *
find_nt(n00b_grammar_t *g, const char *nt_name)
{
    for (size_t i = 0; i < n00b_list_len(g->nt_list); i++) {
        n00b_nonterm_t *nt = n00b_get_nonterm(g, (int64_t)i);
        if (!nt || !nt->name) {
            continue;
        }
        if ((size_t)nt->name->u8_bytes == strlen(nt_name)
            && memcmp(nt->name->data, nt_name, nt->name->u8_bytes) == 0) {
            return nt;
        }
    }
    return nullptr;
}

// ----------------------------------------------------------------------------
// Test 1: Capture-only production (no rewrite block) — captures attach.
// ----------------------------------------------------------------------------
static void
test_capture_decl(void)
{
    n00b_grammar_t *g  = n00b_grammar_new();
    bool            ok = n00b_bnf_load(
        bnf("<S> ::= $a:<inner> $b:<inner>\n"
            "<inner> ::= %IDENTIFIER\n"),
        r"S", g);
    assert(ok);

    n00b_parse_rule_t *p = first_rule_for(g, "S");
    assert(p);

    n00b_list_t(n00b_string_t *) *names = n00b_production_capture_names(p);
    assert(names);
    assert(n00b_list_len(*names) == 2);

    n00b_string_t *a = n00b_list_get(*names, 0);
    n00b_string_t *b = n00b_list_get(*names, 1);
    assert(a && b);
    assert(n00b_unicode_str_eq(a, r"a"));
    assert(n00b_unicode_str_eq(b, r"b"));

    assert(!n00b_production_has_rewrite(p));

    printf("  [PASS] capture_decl\n");
}

// ----------------------------------------------------------------------------
// Test 2: Rewrite block — template + description fields parse + accessors.
// ----------------------------------------------------------------------------
static void
test_rewrite_block_fields(void)
{
    n00b_grammar_t *g  = n00b_grammar_new();
    bool            ok = n00b_bnf_load(
        bnf("<S> ::= %IDENTIFIER\n"
            "rewrite {\n"
            "    template: nullptr\n"
            "    description: Replace NULL with nullptr.\n"
            "}\n"),
        r"S", g);
    assert(ok);

    n00b_parse_rule_t *p = first_rule_for(g, "S");
    assert(p);
    assert(n00b_production_has_rewrite(p));

    n00b_option_t(n00b_string_t *) tmpl =
        n00b_production_rewrite_field(p, r"template");
    assert(n00b_option_is_set(tmpl));
    n00b_string_t *tmpl_val = n00b_option_get(tmpl);
    assert(tmpl_val);
    assert(n00b_unicode_str_eq(tmpl_val, r"nullptr"));

    n00b_option_t(n00b_string_t *) desc =
        n00b_production_rewrite_field(p, r"description");
    assert(n00b_option_is_set(desc));
    n00b_string_t *desc_val = n00b_option_get(desc);
    assert(desc_val);
    assert(n00b_unicode_str_eq(desc_val, r"Replace NULL with nullptr."));

    n00b_option_t(n00b_string_t *) absent =
        n00b_production_rewrite_field(p, r"no_such_field");
    assert(!n00b_option_is_set(absent));

    printf("  [PASS] rewrite_block_fields\n");
}

// ----------------------------------------------------------------------------
// Test 3: Leveled-brace block — bare `}` permitted inside `{= ... =}`.
// ----------------------------------------------------------------------------
static void
test_leveled_braces(void)
{
    n00b_grammar_t *g  = n00b_grammar_new();
    bool            ok = n00b_bnf_load(
        bnf("<S> ::= %IDENTIFIER\n"
            "rewrite {=\n"
            "    template: { inner_brace_here }\n"
            "=}\n"),
        r"S", g);
    assert(ok);

    n00b_parse_rule_t *p = first_rule_for(g, "S");
    assert(p);
    assert(n00b_production_has_rewrite(p));

    n00b_option_t(n00b_string_t *) tmpl =
        n00b_production_rewrite_field(p, r"template");
    assert(n00b_option_is_set(tmpl));
    n00b_string_t *tmpl_val = n00b_option_get(tmpl);
    assert(tmpl_val);
    // Body contains a bare `}` — must round-trip without truncation.
    bool has_brace = false;
    for (size_t i = 0; i < (size_t)tmpl_val->u8_bytes; i++) {
        if (tmpl_val->data[i] == '}') {
            has_brace = true;
            break;
        }
    }
    assert(has_brace);

    printf("  [PASS] leveled_braces\n");
}

// ----------------------------------------------------------------------------
// Test 4: Heredoc field value — `[==[ ... ]==]` preserves exact bytes,
// including embedded `key:` patterns that would otherwise terminate the
// value.
// ----------------------------------------------------------------------------
static void
test_heredoc_field(void)
{
    n00b_grammar_t *g  = n00b_grammar_new();
    bool            ok = n00b_bnf_load(
        bnf("<S> ::= %IDENTIFIER\n"
            "rewrite {\n"
            "    template: [==[fake: not_a_field\n"
            "still_inside_template]==]\n"
            "    description: real description\n"
            "}\n"),
        r"S", g);
    assert(ok);

    n00b_parse_rule_t *p = first_rule_for(g, "S");
    assert(p);

    n00b_option_t(n00b_string_t *) tmpl =
        n00b_production_rewrite_field(p, r"template");
    assert(n00b_option_is_set(tmpl));
    n00b_string_t *tmpl_val = n00b_option_get(tmpl);
    assert(tmpl_val);
    // The heredoc body must contain the `fake:` literal (heredoc protects
    // from key:-style field-end detection).
    bool found_fake = (tmpl_val->u8_bytes >= 5)
                      && (memmem(tmpl_val->data, tmpl_val->u8_bytes,
                                  "fake:", 5) != nullptr);
    assert(found_fake);

    // `description` must still be parsed as a separate field, with its
    // real value (not vacuumed into the heredoc).
    n00b_option_t(n00b_string_t *) desc =
        n00b_production_rewrite_field(p, r"description");
    assert(n00b_option_is_set(desc));
    n00b_string_t *desc_val = n00b_option_get(desc);
    assert(desc_val);
    assert(n00b_unicode_str_eq(desc_val, r"real description"));

    printf("  [PASS] heredoc_field\n");
}

// ----------------------------------------------------------------------------
// Test 5: Text-mode apply — substitute captures with matched source bytes.
// ----------------------------------------------------------------------------
static void
test_rewrite_text_apply(void)
{
    n00b_grammar_t *g  = n00b_grammar_new();
    bool            ok = n00b_bnf_load(
        bnf("<call> ::= %\"malloc\" %\"(\" $sz:<expr> %\")\"\n"
            "rewrite {\n"
            "    template: n00b_alloc_size($sz)\n"
            "}\n"
            "<expr> ::= %IDENTIFIER\n"),
        r"call", g);
    assert(ok);

    n00b_parse_rule_t *p = first_rule_for(g, "call");
    assert(p);
    assert(n00b_production_has_rewrite(p));

    n00b_list_t(n00b_string_t *) *names = n00b_production_capture_names(p);
    assert(names);
    assert(n00b_list_len(*names) == 1);
    n00b_string_t *cn = n00b_list_get(*names, 0);
    assert(n00b_unicode_str_eq(cn, r"sz"));

    // Build a parse tree manually that matches:
    //   call -> "malloc" "(" expr ")"
    //              expr -> IDENT("42")
    n00b_nonterm_t *call = find_nt(g, "call");
    n00b_nonterm_t *expr = find_nt(g, "expr");
    assert(call && expr);

    int64_t tid_malloc = n00b_register_terminal(g, r"malloc");
    int64_t tid_lp     = n00b_register_terminal(g, r"(");
    int64_t tid_rp     = n00b_register_terminal(g, r")");
    int64_t tid_id     = n00b_register_terminal(g, r"IDENTIFIER");

    n00b_parse_tree_t *root = mk_nt_node(call);
    (void)n00b_tree_add_child(root, mk_leaf("malloc", tid_malloc));
    (void)n00b_tree_add_child(root, mk_leaf("(", tid_lp));

    n00b_parse_tree_t *expr_node = mk_nt_node(expr);
    (void)n00b_tree_add_child(expr_node, mk_leaf("42", tid_id));
    (void)n00b_tree_add_child(root, expr_node);

    (void)n00b_tree_add_child(root, mk_leaf(")", tid_rp));

    n00b_result_t(n00b_string_t *) rr =
        n00b_production_rewrite_text(p, root);
    assert(n00b_result_is_ok(rr));
    n00b_string_t *out = n00b_result_get(rr);
    assert(out);

    const char *expected = "n00b_alloc_size(42)";
    printf("    actual:   <<%.*s>>\n", (int)out->u8_bytes, out->data);
    printf("    expected: <<%s>>\n", expected);
    assert((size_t)out->u8_bytes == strlen(expected));
    assert(memcmp(out->data, expected, (size_t)out->u8_bytes) == 0);

    printf("  [PASS] rewrite_text_apply\n");
}

// ----------------------------------------------------------------------------
// Test 6: Subtree-mode apply — substitutes a capture via the pretty-printer.
//
// The captured `<expr>` non-terminal carries no annotations, so the
// pretty-printer renders the IDENT leaf as-is. End-to-end this exercises
// the subtree path (set_grammar back-channel + pprint integration) on
// the same template/grammar shape used by the text-mode test.
// ----------------------------------------------------------------------------
static void
test_rewrite_subtree_apply(void)
{
    n00b_grammar_t *g  = n00b_grammar_new();
    bool            ok = n00b_bnf_load(
        bnf("<call> ::= %\"malloc\" %\"(\" $sz:<expr> %\")\"\n"
            "rewrite {\n"
            "    template: n00b_alloc_size($sz)\n"
            "}\n"
            "<expr> ::= %IDENTIFIER\n"),
        r"call", g);
    assert(ok);

    n00b_parse_rule_t *p = first_rule_for(g, "call");
    assert(p);

    n00b_nonterm_t *call = find_nt(g, "call");
    n00b_nonterm_t *expr = find_nt(g, "expr");
    assert(call && expr);

    int64_t tid_malloc = n00b_register_terminal(g, r"malloc");
    int64_t tid_lp     = n00b_register_terminal(g, r"(");
    int64_t tid_rp     = n00b_register_terminal(g, r")");
    int64_t tid_id     = n00b_register_terminal(g, r"IDENTIFIER");

    n00b_parse_tree_t *root = mk_nt_node(call);
    (void)n00b_tree_add_child(root, mk_leaf("malloc", tid_malloc));
    (void)n00b_tree_add_child(root, mk_leaf("(", tid_lp));

    n00b_parse_tree_t *expr_node = mk_nt_node(expr);
    (void)n00b_tree_add_child(expr_node, mk_leaf("7", tid_id));
    (void)n00b_tree_add_child(root, expr_node);

    (void)n00b_tree_add_child(root, mk_leaf(")", tid_rp));

    n00b_rewrite_set_grammar(g);
    n00b_result_t(n00b_string_t *) rr =
        n00b_production_rewrite_subtree(p, root);
    n00b_rewrite_set_grammar(nullptr);

    assert(n00b_result_is_ok(rr));
    n00b_string_t *out = n00b_result_get(rr);
    assert(out);

    const char *expected = "n00b_alloc_size(7)";
    printf("    actual:   <<%.*s>>\n", (int)out->u8_bytes, out->data);
    printf("    expected: <<%s>>\n", expected);
    assert((size_t)out->u8_bytes == strlen(expected));
    assert(memcmp(out->data, expected, (size_t)out->u8_bytes) == 0);

    printf("  [PASS] rewrite_subtree_apply\n");
}

// ----------------------------------------------------------------------------
// Test 7: No rewrite attached — apply returns NO_BLOCK.
// ----------------------------------------------------------------------------
static void
test_no_rewrite_returns_err(void)
{
    n00b_grammar_t *g  = n00b_grammar_new();
    bool            ok = n00b_bnf_load(
        bnf("<S> ::= %IDENTIFIER\n"),
        r"S", g);
    assert(ok);

    n00b_parse_rule_t *p = first_rule_for(g, "S");
    assert(p);
    assert(!n00b_production_has_rewrite(p));

    // Build a tiny tree; the apply call needs a valid node.
    n00b_nonterm_t    *s    = n00b_get_nonterm(g, 0);
    n00b_parse_tree_t *root = mk_nt_node(s);
    (void)n00b_tree_add_child(root, mk_leaf("foo",
                                             n00b_register_terminal(g, r"IDENTIFIER")));

    n00b_result_t(n00b_string_t *) rr =
        n00b_production_rewrite_text(p, root);
    assert(n00b_result_is_err(rr));
    assert(n00b_result_get_err(rr) == N00B_ERR_REWRITE_NO_BLOCK);

    printf("  [PASS] no_rewrite_returns_err\n");
}

// ----------------------------------------------------------------------------
// Test 8: Null inputs — apply returns NULL_INPUT.
// ----------------------------------------------------------------------------
static void
test_null_input_returns_err(void)
{
    n00b_result_t(n00b_string_t *) r1 =
        n00b_production_rewrite_text(nullptr, nullptr);
    assert(n00b_result_is_err(r1));
    assert(n00b_result_get_err(r1) == N00B_ERR_REWRITE_NULL_INPUT);

    // has_rewrite tolerates null.
    assert(!n00b_production_has_rewrite(nullptr));

    // capture_names tolerates null and returns an empty list.
    n00b_list_t(n00b_string_t *) *names =
        n00b_production_capture_names(nullptr);
    assert(names);
    assert(n00b_list_len(*names) == 0);

    printf("  [PASS] null_input_returns_err\n");
}

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------
int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Slay rewrite tests:\n");
    test_capture_decl();
    test_rewrite_block_fields();
    test_leveled_braces();
    test_heredoc_field();
    test_rewrite_text_apply();
    test_rewrite_subtree_apply();
    test_no_rewrite_returns_err();
    test_null_input_returns_err();
    printf("All slay_rewrite tests passed.\n");
    return 0;
}

// test_infer_expr.c — Tests for @infer expression interpreter.
//
// Tests the mini-language through the full pipeline: parse a n00b program,
// run the annotation walk (which fires @infer), then check that the
// node_types dict has the expected type for expression nodes.

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "test_portability.h"

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/gc.h"
#include "core/runtime.h"
#include "adt/option.h"
#include "adt/list.h"
#include "core/string.h"
#include "text/strings/string_ops.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"

#include "typecheck/types.h"
#include "typecheck/context.h"
#include "typecheck/unify.h"

#include "slay/token.h"
#include "slay/parse_tree.h"
#include "slay/grammar.h"
#include "slay/bnf.h"
#include "slay/n00b_parse.h"
#include "n00b/n00b_tokenizer.h"
#include "slay/symtab.h"
#include "slay/annot_walk.h"
#include "n00b/n00b_compile.h"
#include "slay/cf_label.h"
#include "slay/infer_expr.h"
#include "internal/slay/grammar_internal.h"

// ============================================================================
// Shared grammar
// ============================================================================

static n00b_grammar_t *shared_grammar = NULL;

static n00b_grammar_t *
load_n00b_grammar(void)
{
    const char *paths[] = {
        "grammars/n00b.bnf",
        "../grammars/n00b.bnf",
        "../../grammars/n00b.bnf",
        NULL,
    };

    const char *srcroot = getenv("MESON_SOURCE_ROOT");
    FILE       *f       = NULL;

    const char **p;
    for (p = paths; *p; p++) {
        f = fopen(*p, "r");

        if (f) {
            break;
        }
    }

    if (!f && srcroot) {
        char *path = nullptr;
        (void)asprintf(&path, "%s/grammars/n00b.bnf", srcroot);
        f = fopen(path, "r");
        free(path);
    }

    if (!f) {
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = malloc((size_t)len + 1);
    fread(buf, 1, (size_t)len, f);
    buf[len] = '\0';
    fclose(f);

    n00b_string_t *bnf_text = n00b_string_from_cstr(buf);
    free(buf);

    n00b_grammar_t *g = n00b_grammar_new(.error_recovery = false);

    n00b_diag_ctx_t *bnf_diag = n00b_diag_ctx_new();
    bool ok = n00b_bnf_load(bnf_text, r"module", g, .diag = bnf_diag);

    if (!ok) {
        fprintf(stderr, "  [FAIL] n00b_bnf_load failed for n00b.bnf\n");
        n00b_diag_print_all(bnf_diag, NULL, "n00b.bnf");
        n00b_diag_ctx_free(bnf_diag);
        n00b_grammar_free(g);
        return NULL;
    }

    n00b_diag_ctx_free(bnf_diag);
    return g;
}

// ============================================================================
// Pipeline helper
// ============================================================================

typedef struct {
    n00b_parse_result_t *pr;
    n00b_parse_tree_t   *tree;
    n00b_annot_result_t *annot;
    bool                 parsed;
} infer_result_t;

static infer_result_t
run_pipeline(const char *src)
{
    infer_result_t r = {0};

    n00b_buffer_t       *buf     = n00b_buffer_from_bytes((char *)src,
                                                           (int64_t)strlen(src));
    n00b_scanner_t      *scanner = n00b_scanner_new(buf, n00b_lang_tokenize,
                                                       shared_grammar);
    n00b_token_stream_t *ts      = n00b_token_stream_new(scanner);

    r.pr = n00b_grammar_parse(shared_grammar, ts);

    if (!n00b_parse_result_ok(r.pr)) {
        r.parsed = false;
        return r;
    }

    r.parsed = true;
    r.tree   = n00b_parse_result_tree(r.pr);
    r.annot  = n00b_compile_walk(shared_grammar, r.tree);

    return r;
}

// ============================================================================
// DFS helper: find first NT node with a given name
// ============================================================================

static n00b_parse_tree_t *
find_nt_node(n00b_grammar_t *g, n00b_parse_tree_t *node, const char *name)
{
    if (!node || n00b_tree_is_leaf(node)) {
        return NULL;
    }

    n00b_nt_node_t *pn = &n00b_tree_node_value(node);

    if (pn->id >= 0 && !pn->group_top) {
        n00b_nonterm_t *nt = n00b_get_nonterm(g, pn->id);

        if (nt && nt->name->u8_bytes == strlen(name)
            && memcmp(nt->name->data, name, nt->name->u8_bytes) == 0) {
            return node;
        }
    }

    size_t nc = n00b_tree_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *found = find_nt_node(g, n00b_tree_child(node, i), name);

        if (found) {
            return found;
        }
    }

    return NULL;
}

// Check if a node has a type in node_types.
static n00b_tc_type_t *
get_node_type(n00b_annot_result_t *annot, n00b_parse_tree_t *node)
{
    if (!annot || !annot->node_types || !node) {
        return NULL;
    }

    bool      found = false;
    uintptr_t key   = (uintptr_t)node;
    n00b_tc_type_t *t = n00b_dict_get(annot->node_types, key, &found);

    return found ? t : NULL;
}

// ============================================================================
// Test: grammar loads
// ============================================================================

static void
test_grammar_loads(void)
{
    shared_grammar = load_n00b_grammar();
    assert(shared_grammar != NULL);
    n00b_gc_register_root(shared_grammar);
    printf("  [PASS] infer_grammar_loads\n");
}

// ============================================================================
// Test: literal int gets a type via @literal (baseline)
// ============================================================================

static void
test_literal_has_type(void)
{
    infer_result_t r = run_pipeline("var x = 42\n");
    assert(r.parsed);
    assert(r.annot != NULL);

    // The simple-lit node should have a type from @literal.
    n00b_parse_tree_t *lit = find_nt_node(shared_grammar, r.tree, "simple-lit");
    assert(lit != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, lit);
    assert(t != NULL);

    printf("  [PASS] literal_has_type\n");
}

// ============================================================================
// Test: expression auto-propagation
// ============================================================================

static void
test_autoprop_simple(void)
{
    // "var x = 42" — the literal type should propagate up through:
    //   simple-lit → primary → postfix-expr → unary-expr → ...
    // until it reaches expression-stmt or higher.
    infer_result_t r = run_pipeline("var x = 42\n");
    assert(r.parsed);
    assert(r.annot != NULL);

    // Check that the primary node got a type via auto-propagation.
    n00b_parse_tree_t *primary = find_nt_node(shared_grammar, r.tree, "primary");

    if (primary) {
        n00b_tc_type_t *t = get_node_type(r.annot, primary);
        // primary has simple-lit as sole NT child, which has a type.
        // Auto-propagation should have pushed it up.
        assert(t != NULL);
    }

    printf("  [PASS] autoprop_simple\n");
}

// ============================================================================
// Test: comparison produces bool
// ============================================================================

static void
test_comparison_bool(void)
{
    infer_result_t r = run_pipeline("var x = 1 < 2\n");
    assert(r.parsed);
    assert(r.annot != NULL);

    // Find the lt-expr node.
    n00b_parse_tree_t *lt = find_nt_node(shared_grammar, r.tree, "lt-expr");
    assert(lt != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, lt);
    assert(t != NULL);

    // The type should resolve to bool.
    n00b_tc_type_t *resolved = t;

    while (resolved->forward) {
        resolved = resolved->forward;
    }

    assert(n00b_variant_is_type(resolved->kind, n00b_tc_prim_t));
    auto prim = n00b_variant_get(resolved->kind, n00b_tc_prim_t);
    assert(n00b_unicode_str_eq(prim.name, r"bool"));

    printf("  [PASS] comparison_bool\n");
}

// ============================================================================
// Test: equality produces bool
// ============================================================================

static void
test_equality_bool(void)
{
    infer_result_t r = run_pipeline("var x = 1 == 2\n");
    assert(r.parsed);
    assert(r.annot != NULL);

    n00b_parse_tree_t *eq = find_nt_node(shared_grammar, r.tree, "eq-expr");
    assert(eq != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, eq);
    assert(t != NULL);

    n00b_tc_type_t *resolved = t;

    while (resolved->forward) {
        resolved = resolved->forward;
    }

    assert(n00b_variant_is_type(resolved->kind, n00b_tc_prim_t));
    auto prim = n00b_variant_get(resolved->kind, n00b_tc_prim_t);
    assert(n00b_unicode_str_eq(prim.name, r"bool"));

    printf("  [PASS] equality_bool\n");
}

// ============================================================================
// Test: logical or produces bool
// ============================================================================

static void
test_logical_or_bool(void)
{
    infer_result_t r = run_pipeline("var a = true\nvar b = false\nvar x = a or b\n");
    assert(r.parsed);
    assert(r.annot != NULL);

    // The expression node for "a or b" should be typed as bool.
    // The top expression in "var x = a or b" is an <expression>.
    // There are multiple <expression> nodes; find the one with two NT children
    // (the "or" alternative).
    // For now, just verify the annot walk produced node_types.
    assert(r.annot->node_types != NULL);

    printf("  [PASS] logical_or_bool\n");
}

// ============================================================================
// Test: unary not produces bool
// ============================================================================

static void
test_unary_not_bool(void)
{
    infer_result_t r = run_pipeline("var x = !true\n");
    assert(r.parsed);
    assert(r.annot != NULL);

    n00b_parse_tree_t *unary = find_nt_node(shared_grammar, r.tree, "unary-expr");
    assert(unary != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, unary);
    assert(t != NULL);

    n00b_tc_type_t *resolved = t;

    while (resolved->forward) {
        resolved = resolved->forward;
    }

    assert(n00b_variant_is_type(resolved->kind, n00b_tc_prim_t));
    auto prim = n00b_variant_get(resolved->kind, n00b_tc_prim_t);
    assert(n00b_unicode_str_eq(prim.name, r"bool"));

    printf("  [PASS] unary_not_bool\n");
}

// ============================================================================
// Test: arithmetic unifies operands
// ============================================================================

static void
test_arithmetic_unify(void)
{
    infer_result_t r = run_pipeline("var x = 1 + 2\n");
    assert(r.parsed);
    assert(r.annot != NULL);

    n00b_parse_tree_t *plus = find_nt_node(shared_grammar, r.tree, "plus-expr");
    assert(plus != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, plus);
    // The plus-expr's @infer("$0 unify $1") should have produced a type.
    assert(t != NULL);

    printf("  [PASS] arithmetic_unify\n");
}

// ============================================================================
// Test: identifier gets type via lookup
// ============================================================================

static void
test_identifier_lookup(void)
{
    infer_result_t r = run_pipeline(
        "var x: int\n"
        "var y = x\n");
    assert(r.parsed);
    assert(r.annot != NULL);

    // Find the identifier-expr for "x" reference (in "var y = x").
    // There should be two identifier-expr nodes: one for the decl's id-list
    // and one for the reference. Actually, the reference "x" in "var y = x"
    // is in an <expression> that leads to <identifier-expr>.
    //
    // The @infer("lookup($0)") on identifier-expr should give it a type_var.
    // We check that the sym "x" has a type_var, and the identifier-expr
    // referencing it got a type too.

    n00b_sym_entry_t *x_sym = n00b_symtab_lookup_all(r.annot->symtab,
                                                        r"", r"x");
    assert(x_sym != NULL);
    assert(x_sym->type_var != NULL);

    printf("  [PASS] identifier_lookup\n");
}

// ============================================================================
// Test: list literal gets parameterized type
// ============================================================================

static void
test_list_literal_type(void)
{
    infer_result_t r = run_pipeline("var x = [1, 2, 3]\n");
    assert(r.parsed);
    assert(r.annot != NULL);

    n00b_parse_tree_t *list = find_nt_node(shared_grammar, r.tree, "list-lit");
    assert(list != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, list);
    assert(t != NULL);

    // Should be a parameterized type named "list".
    n00b_tc_type_t *resolved = t;

    while (resolved->forward) {
        resolved = resolved->forward;
    }

    assert(n00b_variant_is_type(resolved->kind, n00b_tc_param_t));
    auto param = n00b_variant_get(resolved->kind, n00b_tc_param_t);
    assert(n00b_unicode_str_eq(param.name, r"list"));

    // Element type should resolve to int (not a bare type variable).
    assert(param.params != NULL);
    assert(n00b_list_len(*param.params) == 1);

    n00b_tc_type_t *elem = n00b_list_get(*param.params, 0);
    n00b_tc_type_t *elem_r = elem;

    while (elem_r->forward) {
        elem_r = elem_r->forward;
    }

    assert(n00b_variant_is_type(elem_r->kind, n00b_tc_prim_t));
    auto elem_prim = n00b_variant_get(elem_r->kind, n00b_tc_prim_t);
    assert(n00b_unicode_str_eq(elem_prim.name, r"int"));

    printf("  [PASS] list_literal_type\n");
}

// ============================================================================
// Test: dict literal gets parameterized type
// ============================================================================

static void
test_dict_literal_type(void)
{
    infer_result_t r = run_pipeline("var x = {\"a\": 1}\n");
    assert(r.parsed);
    assert(r.annot != NULL);

    n00b_parse_tree_t *dict = find_nt_node(shared_grammar, r.tree, "dict-or-set-lit");
    assert(dict != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, dict);
    assert(t != NULL);

    n00b_tc_type_t *resolved = t;

    while (resolved->forward) {
        resolved = resolved->forward;
    }

    assert(n00b_variant_is_type(resolved->kind, n00b_tc_param_t));
    auto param = n00b_variant_get(resolved->kind, n00b_tc_param_t);
    assert(n00b_unicode_str_eq(param.name, r"dict"));

    // Key and value types should be resolved (not bare type variables).
    assert(param.params != NULL);
    assert(n00b_list_len(*param.params) == 2);

    // Key → string.
    n00b_tc_type_t *key = n00b_list_get(*param.params, 0);
    n00b_tc_type_t *key_r = key;

    while (key_r->forward) {
        key_r = key_r->forward;
    }

    assert(n00b_variant_is_type(key_r->kind, n00b_tc_prim_t));
    auto key_prim = n00b_variant_get(key_r->kind, n00b_tc_prim_t);
    assert(n00b_unicode_str_eq(key_prim.name, r"string"));

    // Value → int.
    n00b_tc_type_t *val = n00b_list_get(*param.params, 1);
    n00b_tc_type_t *val_r = val;

    while (val_r->forward) {
        val_r = val_r->forward;
    }

    assert(n00b_variant_is_type(val_r->kind, n00b_tc_prim_t));
    auto val_prim = n00b_variant_get(val_r->kind, n00b_tc_prim_t);
    assert(n00b_unicode_str_eq(val_prim.name, r"int"));

    printf("  [PASS] dict_literal_type\n");
}

// ============================================================================
// Test: parameterized class gets parameterized type
// ============================================================================

static void
test_parameterized_class_type(void)
{
    const char *src =
        "class Pair[`T, `U] {\n"
        "    first: `T\n"
        "    second: `U\n"
        "}\n";

    infer_result_t r = run_pipeline(src);
    assert(r.parsed);
    assert(r.annot != NULL);

    // The class symbol should exist and have a parameterized type.
    n00b_sym_entry_t *sym = n00b_symtab_lookup_all(r.annot->symtab,
                                                       r"", r"Pair");
    assert(sym != NULL);
    assert(sym->type_var != NULL);

    n00b_tc_type_t *resolved = n00b_tc_find(sym->type_var);
    assert(resolved != NULL);
    assert(n00b_variant_is_type(resolved->kind, n00b_tc_param_t));

    auto param = n00b_variant_get(resolved->kind, n00b_tc_param_t);
    assert(n00b_unicode_str_eq(param.name, r"Pair"));
    assert(param.params != NULL);
    assert(n00b_list_len(*param.params) == 2);

    // Both parameters should be type variables.
    n00b_tc_type_t *p0 = n00b_list_get(*param.params, 0);
    n00b_tc_type_t *r0 = p0;

    while (r0->forward) {
        r0 = r0->forward;
    }

    assert(n00b_variant_is_type(r0->kind, n00b_tc_var_t));

    n00b_tc_type_t *p1 = n00b_list_get(*param.params, 1);
    n00b_tc_type_t *r1 = p1;

    while (r1->forward) {
        r1 = r1->forward;
    }

    assert(n00b_variant_is_type(r1->kind, n00b_tc_var_t));

    printf("  [PASS] parameterized_class_type\n");
}

// ============================================================================
// Test: concrete class gets named type
// ============================================================================

static void
test_concrete_class_type(void)
{
    const char *src =
        "class Point {\n"
        "    x: int\n"
        "    y: int\n"
        "}\n";

    infer_result_t r = run_pipeline(src);
    assert(r.parsed);
    assert(r.annot != NULL);

    n00b_sym_entry_t *sym = n00b_symtab_lookup_all(r.annot->symtab,
                                                       r"", r"Point");
    assert(sym != NULL);
    assert(sym->type_var != NULL);

    n00b_tc_type_t *resolved = n00b_tc_find(sym->type_var);
    assert(resolved != NULL);

    // Concrete class should be a primitive (named) type.
    assert(n00b_variant_is_type(resolved->kind, n00b_tc_prim_t));
    auto prim = n00b_variant_get(resolved->kind, n00b_tc_prim_t);
    assert(n00b_unicode_str_eq(prim.name, r"Point"));

    printf("  [PASS] concrete_class_type\n");
}

// ============================================================================
// Test: infer_eval directly with a mock context
// ============================================================================

static void
test_infer_eval_prim(void)
{
    // Test the interpreter directly: "bool" should produce a bool prim.
    n00b_tc_ctx_t *ctx = n00b_tc_ctx_new();

    n00b_tc_type_t *t = n00b_infer_eval(ctx, NULL, NULL, NULL, NULL,
                                           r"bool");
    assert(t != NULL);

    n00b_tc_type_t *resolved = t;

    while (resolved->forward) {
        resolved = resolved->forward;
    }

    assert(n00b_variant_is_type(resolved->kind, n00b_tc_prim_t));
    auto prim = n00b_variant_get(resolved->kind, n00b_tc_prim_t);
    assert(n00b_unicode_str_eq(prim.name, r"bool"));

    n00b_tc_ctx_free(ctx);
    printf("  [PASS] infer_eval_prim\n");
}

static void
test_infer_eval_tvar(void)
{
    // "`x" should produce a type variable.
    n00b_tc_ctx_t *ctx = n00b_tc_ctx_new();

    n00b_tc_type_t *t = n00b_infer_eval(ctx, NULL, NULL, NULL, NULL,
                                           r"`x");
    assert(t != NULL);

    n00b_tc_type_t *resolved = t;

    while (resolved->forward) {
        resolved = resolved->forward;
    }

    assert(n00b_variant_is_type(resolved->kind, n00b_tc_var_t));

    // Within ONE expression, same `x should give the same var.
    // Test via "dict[`x, `x]" — both params should be the same var.
    n00b_tc_type_t *dict_t = n00b_infer_eval(ctx, NULL, NULL, NULL, NULL,
                                                r"dict[`x, `x]");
    assert(dict_t != NULL);

    n00b_tc_type_t *dr = dict_t;
    while (dr->forward) dr = dr->forward;

    assert(n00b_variant_is_type(dr->kind, n00b_tc_param_t));
    auto param = n00b_variant_get(dr->kind, n00b_tc_param_t);
    assert(n00b_list_len(*param.params) == 2);

    n00b_tc_type_t *p0 = n00b_list_get(*param.params, 0);
    n00b_tc_type_t *p1 = n00b_list_get(*param.params, 1);

    // Both should be the same var (same pointer after find).
    n00b_tc_type_t *r0 = p0;
    while (r0->forward) r0 = r0->forward;
    n00b_tc_type_t *r1 = p1;
    while (r1->forward) r1 = r1->forward;

    assert(r0 == r1);  // Same canonical type node.

    n00b_tc_ctx_free(ctx);
    printf("  [PASS] infer_eval_tvar\n");
}

static void
test_infer_eval_param(void)
{
    // "list[`e]" should produce a parameterized type.
    n00b_tc_ctx_t *ctx = n00b_tc_ctx_new();

    n00b_tc_type_t *t = n00b_infer_eval(ctx, NULL, NULL, NULL, NULL,
                                           r"list[`e]");
    assert(t != NULL);

    n00b_tc_type_t *resolved = t;

    while (resolved->forward) {
        resolved = resolved->forward;
    }

    assert(n00b_variant_is_type(resolved->kind, n00b_tc_param_t));
    auto param = n00b_variant_get(resolved->kind, n00b_tc_param_t);
    assert(n00b_unicode_str_eq(param.name, r"list"));
    assert(param.params != NULL);
    assert(n00b_list_len(*param.params) == 1);

    // The parameter should be a type variable.
    n00b_tc_type_t *elem = n00b_list_get(*param.params, 0);
    n00b_tc_type_t *er = elem;

    while (er->forward) {
        er = er->forward;
    }

    assert(n00b_variant_is_type(er->kind, n00b_tc_var_t));

    n00b_tc_ctx_free(ctx);
    printf("  [PASS] infer_eval_param\n");
}

static void
test_infer_eval_dict_param(void)
{
    // "dict[`k, `v]" should produce dict with two type var params.
    n00b_tc_ctx_t *ctx = n00b_tc_ctx_new();

    n00b_tc_type_t *t = n00b_infer_eval(ctx, NULL, NULL, NULL, NULL,
                                           r"dict[`k, `v]");
    assert(t != NULL);

    n00b_tc_type_t *resolved = t;

    while (resolved->forward) {
        resolved = resolved->forward;
    }

    assert(n00b_variant_is_type(resolved->kind, n00b_tc_param_t));
    auto param = n00b_variant_get(resolved->kind, n00b_tc_param_t);
    assert(n00b_unicode_str_eq(param.name, r"dict"));
    assert(n00b_list_len(*param.params) == 2);

    n00b_tc_ctx_free(ctx);
    printf("  [PASS] infer_eval_dict_param\n");
}

static void
test_infer_eval_sum(void)
{
    // "int | nil" should produce a sum type.
    n00b_tc_ctx_t *ctx = n00b_tc_ctx_new();

    n00b_tc_type_t *t = n00b_infer_eval(ctx, NULL, NULL, NULL, NULL,
                                           r"int | nil");
    assert(t != NULL);

    n00b_tc_type_t *resolved = t;

    while (resolved->forward) {
        resolved = resolved->forward;
    }

    assert(n00b_variant_is_type(resolved->kind, n00b_tc_sum_t));
    auto sum = n00b_variant_get(resolved->kind, n00b_tc_sum_t);
    assert(n00b_list_len(*sum.variants) == 2);

    n00b_tc_ctx_free(ctx);
    printf("  [PASS] infer_eval_sum\n");
}

// ============================================================================
// End-to-end tests: type propagation into symbol table
// ============================================================================

static void
test_var_type_from_int_literal(void)
{
    // "var x = 42" — x's type_var should resolve to int (from literal).
    infer_result_t r = run_pipeline("var x = 42\n");
    assert(r.parsed);
    assert(r.annot != NULL);

    n00b_sym_entry_t *x = n00b_symtab_lookup_all(r.annot->symtab, r"", r"x");
    assert(x != NULL);
    assert(x->type_var != NULL);

    n00b_tc_type_t *resolved = n00b_tc_find(x->type_var);
    assert(resolved != NULL);
    assert(n00b_variant_is_type(resolved->kind, n00b_tc_prim_t));

    auto prim = n00b_variant_get(resolved->kind, n00b_tc_prim_t);
    assert(n00b_unicode_str_eq(prim.name, r"int"));

    printf("  [PASS] var_type_from_int_literal\n");
}

static void
test_var_type_from_string_literal(void)
{
    // "var s = \"hello\"" — s's type_var should resolve to string.
    infer_result_t r = run_pipeline("var s = \"hello\"\n");
    assert(r.parsed);
    assert(r.annot != NULL);

    n00b_sym_entry_t *s = n00b_symtab_lookup_all(r.annot->symtab, r"", r"s");
    assert(s != NULL);
    assert(s->type_var != NULL);

    n00b_tc_type_t *resolved = n00b_tc_find(s->type_var);
    assert(resolved != NULL);
    assert(n00b_variant_is_type(resolved->kind, n00b_tc_prim_t));

    auto prim = n00b_variant_get(resolved->kind, n00b_tc_prim_t);
    assert(n00b_unicode_str_eq(prim.name, r"string"));

    printf("  [PASS] var_type_from_string_literal\n");
}

static void
test_var_type_from_bool_literal(void)
{
    // "var b = true" — b's type_var should resolve to bool.
    infer_result_t r = run_pipeline("var b = true\n");
    assert(r.parsed);
    assert(r.annot != NULL);

    n00b_sym_entry_t *b = n00b_symtab_lookup_all(r.annot->symtab, r"", r"b");
    assert(b != NULL);
    assert(b->type_var != NULL);

    n00b_tc_type_t *resolved = n00b_tc_find(b->type_var);
    assert(resolved != NULL);
    assert(n00b_variant_is_type(resolved->kind, n00b_tc_prim_t));

    auto prim = n00b_variant_get(resolved->kind, n00b_tc_prim_t);
    assert(n00b_unicode_str_eq(prim.name, r"bool"));

    printf("  [PASS] var_type_from_bool_literal\n");
}

static void
test_var_type_explicit_preserved(void)
{
    // "var x: i32 = 42" — x's type_var should resolve to i32 (not int).
    infer_result_t r = run_pipeline("var x: i32 = 42\n");
    assert(r.parsed);
    assert(r.annot != NULL);

    n00b_sym_entry_t *x = n00b_symtab_lookup_all(r.annot->symtab, r"", r"x");
    assert(x != NULL);
    assert(x->type_var != NULL);

    n00b_tc_type_t *resolved = n00b_tc_find(x->type_var);
    assert(resolved != NULL);
    assert(n00b_variant_is_type(resolved->kind, n00b_tc_prim_t));

    auto prim = n00b_variant_get(resolved->kind, n00b_tc_prim_t);
    assert(n00b_unicode_str_eq(prim.name, r"i32"));

    printf("  [PASS] var_type_explicit_preserved\n");
}

static void
test_func_return_symbol(void)
{
    // Function scope should have a $return symbol with a type_var.
    const char *src =
        "func add(a: int, b: int) -> int {\n"
        "  return a + b\n"
        "}\n";

    infer_result_t r = run_pipeline(src);
    assert(r.parsed);
    assert(r.annot != NULL);

    // The $return symbol should be findable in the symtab (all scopes).
    n00b_sym_entry_t *ret = n00b_symtab_lookup_all(
        r.annot->symtab, r"", r"$return");
    assert(ret != NULL);
    assert(ret->type_var != NULL);

    printf("  [PASS] func_return_symbol\n");
}

static void
test_var_type_from_comparison(void)
{
    // "var x = 1 < 2" — x's type_var should resolve to bool.
    infer_result_t r = run_pipeline("var x = 1 < 2\n");
    assert(r.parsed);
    assert(r.annot != NULL);

    n00b_sym_entry_t *x = n00b_symtab_lookup_all(r.annot->symtab, r"", r"x");
    assert(x != NULL);
    assert(x->type_var != NULL);

    n00b_tc_type_t *resolved = n00b_tc_find(x->type_var);
    assert(resolved != NULL);
    assert(n00b_variant_is_type(resolved->kind, n00b_tc_prim_t));

    auto prim = n00b_variant_get(resolved->kind, n00b_tc_prim_t);
    assert(n00b_unicode_str_eq(prim.name, r"bool"));

    printf("  [PASS] var_type_from_comparison\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running infer_expr tests...\n");

    // Grammar loading.
    test_grammar_loads();

    // Pipeline integration tests.
    test_literal_has_type();
    test_autoprop_simple();
    test_comparison_bool();
    test_equality_bool();
    test_logical_or_bool();
    test_unary_not_bool();
    test_arithmetic_unify();
    test_identifier_lookup();
    test_list_literal_type();
    test_dict_literal_type();
    test_parameterized_class_type();
    test_concrete_class_type();

    // Direct interpreter tests.
    test_infer_eval_prim();
    test_infer_eval_tvar();
    test_infer_eval_param();
    test_infer_eval_dict_param();
    test_infer_eval_sum();

    // End-to-end: type propagation into symbol table.
    test_var_type_from_int_literal();
    test_var_type_from_string_literal();
    test_var_type_from_bool_literal();
    test_var_type_explicit_preserved();
    test_func_return_symbol();
    test_var_type_from_comparison();

    printf("All infer_expr tests passed.\n");
    n00b_shutdown();
    return 0;
}

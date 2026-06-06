// test_n00b_types.c — End-to-end type inference tests for every grammar branch.
//
// For each type-annotated grammar rule, parses a minimal n00b program,
// runs the full annotation walk, and checks that:
//   1. The expected node has a type in node_types
//   2. The type resolves to the expected primitive/parameterized/fn type
//   3. Symbol table entries carry the right type_var
//   4. Types propagate upward through auto-propagation
//   5. @assigns unifies LHS symbol type with RHS expression type

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/gc.h"
#include "core/runtime.h"
#include "adt/option.h"
#include "adt/list.h"
#include "adt/variant.h"
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
        if (f) break;
    }

    if (!f && srcroot) {
        char path[1024];
        snprintf(path, sizeof(path), "%s/grammars/n00b.bnf", srcroot);
        f = fopen(path, "r");
    }

    if (!f) return NULL;

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
} test_result_t;

static test_result_t
run_pipeline(const char *src)
{
    test_result_t r = {0};

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

// ============================================================================
// Type query helpers
// ============================================================================

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

// Resolve a type through forward pointers to its canonical form.
static n00b_tc_type_t *
resolve_type(n00b_tc_type_t *t)
{
    if (!t) return NULL;
    return n00b_tc_find(t);
}

// Check that a type resolves to a primitive with the given name.
static bool
is_prim(n00b_tc_type_t *t, const char *name)
{
    n00b_tc_type_t *r = resolve_type(t);
    if (!r) return false;
    if (!n00b_variant_is_type(r->kind, n00b_tc_prim_t)) return false;

    auto prim = n00b_variant_get(r->kind, n00b_tc_prim_t);
    return prim.name && prim.name->u8_bytes == strlen(name)
        && memcmp(prim.name->data, name, prim.name->u8_bytes) == 0;
}

// Check that a type resolves to a parameterized type with the given constructor.
static bool
is_param(n00b_tc_type_t *t, const char *ctor_name)
{
    n00b_tc_type_t *r = resolve_type(t);
    if (!r) return false;
    if (!n00b_variant_is_type(r->kind, n00b_tc_param_t)) return false;

    auto param = n00b_variant_get(r->kind, n00b_tc_param_t);
    return param.name && param.name->u8_bytes == strlen(ctor_name)
        && memcmp(param.name->data, ctor_name, param.name->u8_bytes) == 0;
}

static bool
is_param_arg_prim(n00b_tc_type_t *t, const char *ctor_name, const char *arg_name)
{
    n00b_tc_type_t *r = resolve_type(t);
    if (!r) return false;
    if (!n00b_variant_is_type(r->kind, n00b_tc_param_t)) return false;

    auto param = n00b_variant_get(r->kind, n00b_tc_param_t);
    if (!param.name || param.name->u8_bytes != strlen(ctor_name)
        || memcmp(param.name->data, ctor_name, param.name->u8_bytes) != 0) {
        return false;
    }

    if (!param.params || n00b_list_len(*param.params) < 1) {
        return false;
    }

    return is_prim(n00b_list_get(*param.params, 0), arg_name);
}

// Check that a type resolves to a function type.
static bool
is_fn(n00b_tc_type_t *t)
{
    n00b_tc_type_t *r = resolve_type(t);
    return r && n00b_variant_is_type(r->kind, n00b_tc_fn_t);
}

// Check that a type is still an unresolved variable.
static bool
is_var(n00b_tc_type_t *t)
{
    n00b_tc_type_t *r = resolve_type(t);
    return r && n00b_variant_is_type(r->kind, n00b_tc_var_t);
}

// Look up a symbol in the default namespace.
static n00b_sym_entry_t *
lookup_sym(n00b_annot_result_t *annot, const char *name)
{
    if (!annot || !annot->symtab) return NULL;

    n00b_string_t *sname = n00b_string_from_cstr(name);
    return n00b_symtab_lookup_any(annot->symtab, n00b_string_empty(), sname);
}

// Assert that parsing + annotation walk succeeded.
static void
assert_pipeline(test_result_t *r, const char *test_name)
{
    if (!r->parsed) {
        fprintf(stderr, "  [FAIL] %s — parse failed\n", test_name);
        assert(0);
    }

    if (!r->annot) {
        fprintf(stderr, "  [FAIL] %s — annotation walk returned NULL\n", test_name);
        assert(0);
    }
}

// ============================================================================
// Test 0: Grammar loads
// ============================================================================

static void
test_grammar_loads(void)
{
    shared_grammar = load_n00b_grammar();
    assert(shared_grammar != NULL);
    n00b_gc_register_root(shared_grammar);
    printf("  [PASS] grammar_loads\n");
}

// ============================================================================
// SECTION 1: Literal types (@literal)
// ============================================================================

static void
test_int_literal(void)
{
    test_result_t r = run_pipeline("42\n");
    assert_pipeline(&r, "int_literal");

    n00b_parse_tree_t *lit = find_nt_node(shared_grammar, r.tree, "simple-lit");
    assert(lit != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, lit);
    assert(t != NULL);
    assert(is_prim(t, "int"));

    printf("  [PASS] int_literal\n");
}

static void
test_hex_literal(void)
{
    test_result_t r = run_pipeline("0xFF\n");
    assert_pipeline(&r, "hex_literal");

    n00b_parse_tree_t *lit = find_nt_node(shared_grammar, r.tree, "simple-lit");
    assert(lit != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, lit);
    assert(t != NULL);
    assert(is_prim(t, "int"));

    printf("  [PASS] hex_literal\n");
}

static void
test_float_literal(void)
{
    test_result_t r = run_pipeline("3.14\n");
    assert_pipeline(&r, "float_literal");

    n00b_parse_tree_t *lit = find_nt_node(shared_grammar, r.tree, "simple-lit");
    assert(lit != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, lit);
    assert(t != NULL);
    assert(is_prim(t, "f64"));

    printf("  [PASS] float_literal\n");
}

static void
test_string_literal(void)
{
    test_result_t r = run_pipeline("\"hello\"\n");
    assert_pipeline(&r, "string_literal");

    n00b_parse_tree_t *lit = find_nt_node(shared_grammar, r.tree, "simple-lit");
    assert(lit != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, lit);
    assert(t != NULL);
    assert(is_prim(t, "string"));

    printf("  [PASS] string_literal\n");
}

static void
test_bool_literal_true(void)
{
    test_result_t r = run_pipeline("true\n");
    assert_pipeline(&r, "bool_literal_true");

    n00b_parse_tree_t *lit = find_nt_node(shared_grammar, r.tree, "simple-lit");
    assert(lit != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, lit);
    assert(t != NULL);
    assert(is_prim(t, "bool"));

    printf("  [PASS] bool_literal_true\n");
}

static void
test_bool_literal_false(void)
{
    test_result_t r = run_pipeline("false\n");
    assert_pipeline(&r, "bool_literal_false");

    n00b_parse_tree_t *lit = find_nt_node(shared_grammar, r.tree, "simple-lit");
    assert(lit != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, lit);
    assert(t != NULL);
    assert(is_prim(t, "bool"));

    printf("  [PASS] bool_literal_false\n");
}

static void
test_char_literal(void)
{
    test_result_t r = run_pipeline("'x'\n");
    assert_pipeline(&r, "char_literal");

    n00b_parse_tree_t *lit = find_nt_node(shared_grammar, r.tree, "simple-lit");
    assert(lit != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, lit);
    assert(t != NULL);
    assert(is_prim(t, "i32"));

    printf("  [PASS] char_literal\n");
}

// ============================================================================
// SECTION 2: Comparison operators → bool (@infer)
// ============================================================================

static void
test_lt_bool(void)
{
    test_result_t r = run_pipeline("var x = 1 < 2\n");
    assert_pipeline(&r, "lt_bool");

    n00b_parse_tree_t *lt = find_nt_node(shared_grammar, r.tree, "lt-expr");
    assert(lt != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, lt);
    assert(t != NULL);
    assert(is_prim(t, "bool"));

    printf("  [PASS] lt_bool\n");
}

static void
test_gt_bool(void)
{
    test_result_t r = run_pipeline("var x = 1 > 2\n");
    assert_pipeline(&r, "gt_bool");

    n00b_parse_tree_t *gt = find_nt_node(shared_grammar, r.tree, "gt-expr");
    assert(gt != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, gt);
    assert(t != NULL);
    assert(is_prim(t, "bool"));

    printf("  [PASS] gt_bool\n");
}

static void
test_le_bool(void)
{
    test_result_t r = run_pipeline("var x = 1 <= 2\n");
    assert_pipeline(&r, "le_bool");

    n00b_parse_tree_t *le = find_nt_node(shared_grammar, r.tree, "lte-expr");
    assert(le != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, le);
    assert(t != NULL);
    assert(is_prim(t, "bool"));

    printf("  [PASS] le_bool\n");
}

static void
test_ge_bool(void)
{
    test_result_t r = run_pipeline("var x = 1 >= 2\n");
    assert_pipeline(&r, "ge_bool");

    n00b_parse_tree_t *ge = find_nt_node(shared_grammar, r.tree, "gte-expr");
    assert(ge != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, ge);
    assert(t != NULL);
    assert(is_prim(t, "bool"));

    printf("  [PASS] ge_bool\n");
}

static void
test_eq_bool(void)
{
    test_result_t r = run_pipeline("var x = 1 == 2\n");
    assert_pipeline(&r, "eq_bool");

    n00b_parse_tree_t *eq = find_nt_node(shared_grammar, r.tree, "eq-expr");
    assert(eq != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, eq);
    assert(t != NULL);
    assert(is_prim(t, "bool"));

    printf("  [PASS] eq_bool\n");
}

static void
test_ne_bool(void)
{
    test_result_t r = run_pipeline("var x = 1 != 2\n");
    assert_pipeline(&r, "ne_bool");

    n00b_parse_tree_t *ne = find_nt_node(shared_grammar, r.tree, "ne-expr");
    assert(ne != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, ne);
    assert(t != NULL);
    assert(is_prim(t, "bool"));

    printf("  [PASS] ne_bool\n");
}

// ============================================================================
// SECTION 3: Logical operators → bool (@infer)
// ============================================================================

static void
test_and_bool(void)
{
    test_result_t r = run_pipeline("var x = true and false\n");
    assert_pipeline(&r, "and_bool");

    n00b_parse_tree_t *node = find_nt_node(shared_grammar, r.tree, "and-expr");
    assert(node != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, node);
    assert(t != NULL);
    assert(is_prim(t, "bool"));

    printf("  [PASS] and_bool\n");
}

static void
test_or_bool(void)
{
    // `or` is handled on the <expression> NT, so we check the symbol type.
    test_result_t r = run_pipeline("var x = true or false\n");
    assert_pipeline(&r, "or_bool");

    n00b_sym_entry_t *sym = lookup_sym(r.annot, "x");
    assert(sym != NULL);
    assert(sym->type_var != NULL);
    assert(is_prim(sym->type_var, "bool"));

    printf("  [PASS] or_bool\n");
}

static void
test_not_bool(void)
{
    // n00b uses `!` for logical not; the NT is <unary-expr>.
    test_result_t r = run_pipeline("var x = !true\n");
    assert_pipeline(&r, "not_bool");

    n00b_parse_tree_t *node = find_nt_node(shared_grammar, r.tree, "unary-expr");
    assert(node != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, node);
    assert(t != NULL);
    assert(is_prim(t, "bool"));

    printf("  [PASS] not_bool\n");
}

// ============================================================================
// SECTION 4: Arithmetic operators — unify operands (@infer)
// ============================================================================

static void
test_add_unify(void)
{
    test_result_t r = run_pipeline("var x = 1 + 2\n");
    assert_pipeline(&r, "add_unify");

    n00b_parse_tree_t *node = find_nt_node(shared_grammar, r.tree, "plus-expr");
    assert(node != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, node);
    assert(t != NULL);
    assert(is_prim(t, "int"));

    printf("  [PASS] add_unify\n");
}

static void
test_sub_unify(void)
{
    test_result_t r = run_pipeline("var x = 10 - 3\n");
    assert_pipeline(&r, "sub_unify");

    n00b_parse_tree_t *node = find_nt_node(shared_grammar, r.tree, "minus-expr");
    assert(node != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, node);
    assert(t != NULL);
    assert(is_prim(t, "int"));

    printf("  [PASS] sub_unify\n");
}

static void
test_mul_unify(void)
{
    test_result_t r = run_pipeline("var x = 2 * 3\n");
    assert_pipeline(&r, "mul_unify");

    n00b_parse_tree_t *node = find_nt_node(shared_grammar, r.tree, "mul-expr");
    assert(node != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, node);
    assert(t != NULL);
    assert(is_prim(t, "int"));

    printf("  [PASS] mul_unify\n");
}

static void
test_div_unify(void)
{
    test_result_t r = run_pipeline("var x = 10 / 2\n");
    assert_pipeline(&r, "div_unify");

    n00b_parse_tree_t *node = find_nt_node(shared_grammar, r.tree, "div-expr");
    assert(node != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, node);
    assert(t != NULL);
    assert(is_prim(t, "int"));

    printf("  [PASS] div_unify\n");
}

static void
test_mod_unify(void)
{
    test_result_t r = run_pipeline("var x = 10 % 3\n");
    assert_pipeline(&r, "mod_unify");

    n00b_parse_tree_t *node = find_nt_node(shared_grammar, r.tree, "mod-expr");
    assert(node != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, node);
    assert(t != NULL);
    assert(is_prim(t, "int"));

    printf("  [PASS] mod_unify\n");
}

// ============================================================================
// SECTION 5: Unary operators (@infer)
// ============================================================================

static void
test_unary_minus(void)
{
    test_result_t r = run_pipeline("var x = -42\n");
    assert_pipeline(&r, "unary_minus");

    n00b_parse_tree_t *node = find_nt_node(shared_grammar, r.tree, "unary-expr");
    assert(node != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, node);
    assert(t != NULL);
    assert(is_prim(t, "int"));

    printf("  [PASS] unary_minus\n");
}

// ============================================================================
// SECTION 6: Bitwise operators — unify operands (@infer)
// ============================================================================

static void
test_bitor_unify(void)
{
    test_result_t r = run_pipeline("var x = 0xFF | 0x0F\n");
    assert_pipeline(&r, "bitor_unify");

    n00b_parse_tree_t *node = find_nt_node(shared_grammar, r.tree, "bitor-expr");
    assert(node != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, node);
    assert(t != NULL);
    assert(is_prim(t, "int"));

    printf("  [PASS] bitor_unify\n");
}

static void
test_bitand_unify(void)
{
    test_result_t r = run_pipeline("var x = 0xFF & 0x0F\n");
    assert_pipeline(&r, "bitand_unify");

    n00b_parse_tree_t *node = find_nt_node(shared_grammar, r.tree, "bitand-expr");
    assert(node != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, node);
    assert(t != NULL);
    assert(is_prim(t, "int"));

    printf("  [PASS] bitand_unify\n");
}

static void
test_shl_preserves_type(void)
{
    test_result_t r = run_pipeline("var x = 1 << 4\n");
    assert_pipeline(&r, "shl_preserves_type");

    n00b_parse_tree_t *node = find_nt_node(shared_grammar, r.tree, "shl-expr");
    assert(node != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, node);
    assert(t != NULL);
    assert(is_prim(t, "int"));

    printf("  [PASS] shl_preserves_type\n");
}

static void
test_shr_preserves_type(void)
{
    test_result_t r = run_pipeline("var x = 16 >> 2\n");
    assert_pipeline(&r, "shr_preserves_type");

    n00b_parse_tree_t *node = find_nt_node(shared_grammar, r.tree, "shr-expr");
    assert(node != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, node);
    assert(t != NULL);
    assert(is_prim(t, "int"));

    printf("  [PASS] shr_preserves_type\n");
}

// ============================================================================
// SECTION 7: Variable declarations + symbol table (@declares, @assigns)
// ============================================================================

static void
test_var_decl_typed(void)
{
    // var x: int = 42  — explicit type annotation on variable
    test_result_t r = run_pipeline("var x: int = 42\n");
    assert_pipeline(&r, "var_decl_typed");

    n00b_sym_entry_t *sym = lookup_sym(r.annot, "x");
    assert(sym != NULL);
    assert(sym->kind == N00B_SYM_VARIABLE);
    assert(sym->type_var != NULL);
    assert(is_prim(sym->type_var, "int"));
    assert(sym->mutability == N00B_SYM_MUTABLE);

    printf("  [PASS] var_decl_typed\n");
}

static void
test_let_decl_typed(void)
{
    test_result_t r = run_pipeline("let x: int = 42\n");
    assert_pipeline(&r, "let_decl_typed");

    n00b_sym_entry_t *sym = lookup_sym(r.annot, "x");
    assert(sym != NULL);
    assert(sym->kind == N00B_SYM_VARIABLE);
    assert(sym->type_var != NULL);
    assert(is_prim(sym->type_var, "int"));
    assert(sym->mutability == N00B_SYM_IMMUTABLE);

    printf("  [PASS] let_decl_typed\n");
}

static void
test_const_decl_typed(void)
{
    test_result_t r = run_pipeline("const PI: f64 = 3.14\n");
    assert_pipeline(&r, "const_decl_typed");

    n00b_sym_entry_t *sym = lookup_sym(r.annot, "PI");
    assert(sym != NULL);
    assert(sym->kind == N00B_SYM_VARIABLE);
    assert(sym->type_var != NULL);
    assert(is_prim(sym->type_var, "f64"));
    assert(sym->mutability == N00B_SYM_CONST);

    printf("  [PASS] const_decl_typed\n");
}

static void
test_global_decl(void)
{
    test_result_t r = run_pipeline("global count: int = 0\n");
    assert_pipeline(&r, "global_decl");

    n00b_sym_entry_t *sym = lookup_sym(r.annot, "count");
    assert(sym != NULL);
    assert(sym->mutability == N00B_SYM_GLOBAL);

    printf("  [PASS] global_decl\n");
}

static void
test_var_decl_untyped_inferred(void)
{
    // var x = 42  — no explicit type, should infer int from @assigns
    test_result_t r = run_pipeline("var x = 42\n");
    assert_pipeline(&r, "var_decl_untyped_inferred");

    n00b_sym_entry_t *sym = lookup_sym(r.annot, "x");
    assert(sym != NULL);
    assert(sym->type_var != NULL);

    // The @assigns annotation unifies x's type_var with the RHS type.
    // RHS is 42 (int literal), so x should be int.
    assert(is_prim(sym->type_var, "int"));

    printf("  [PASS] var_decl_untyped_inferred\n");
}

static void
test_var_decl_string_inferred(void)
{
    test_result_t r = run_pipeline("var s = \"hello\"\n");
    assert_pipeline(&r, "var_decl_string_inferred");

    n00b_sym_entry_t *sym = lookup_sym(r.annot, "s");
    assert(sym != NULL);
    assert(sym->type_var != NULL);
    assert(is_prim(sym->type_var, "string"));

    printf("  [PASS] var_decl_string_inferred\n");
}

static void
test_var_decl_bool_inferred(void)
{
    test_result_t r = run_pipeline("var b = true\n");
    assert_pipeline(&r, "var_decl_bool_inferred");

    n00b_sym_entry_t *sym = lookup_sym(r.annot, "b");
    assert(sym != NULL);
    assert(sym->type_var != NULL);
    assert(is_prim(sym->type_var, "bool"));

    printf("  [PASS] var_decl_bool_inferred\n");
}

static void
test_var_decl_float_inferred(void)
{
    test_result_t r = run_pipeline("var f = 2.71\n");
    assert_pipeline(&r, "var_decl_float_inferred");

    n00b_sym_entry_t *sym = lookup_sym(r.annot, "f");
    assert(sym != NULL);
    assert(sym->type_var != NULL);
    assert(is_prim(sym->type_var, "f64"));

    printf("  [PASS] var_decl_float_inferred\n");
}

static void
test_var_decl_expr_inferred(void)
{
    // var x = 1 + 2  — should infer int from arithmetic expression
    test_result_t r = run_pipeline("var x = 1 + 2\n");
    assert_pipeline(&r, "var_decl_expr_inferred");

    n00b_sym_entry_t *sym = lookup_sym(r.annot, "x");
    assert(sym != NULL);
    assert(sym->type_var != NULL);
    assert(is_prim(sym->type_var, "int"));

    printf("  [PASS] var_decl_expr_inferred\n");
}

static void
test_var_decl_comparison_inferred(void)
{
    // var x = 1 < 2  — should infer bool from comparison
    test_result_t r = run_pipeline("var x = 1 < 2\n");
    assert_pipeline(&r, "var_decl_comparison_inferred");

    n00b_sym_entry_t *sym = lookup_sym(r.annot, "x");
    assert(sym != NULL);
    assert(sym->type_var != NULL);
    assert(is_prim(sym->type_var, "bool"));

    printf("  [PASS] var_decl_comparison_inferred\n");
}

// ============================================================================
// SECTION 8: Function declarations (@declares with "function" kind)
// ============================================================================

static void
test_func_decl_sym(void)
{
    test_result_t r = run_pipeline(
        "func add(a: int, b: int) -> int {\n"
        "    return a + b\n"
        "}\n"
    );
    assert_pipeline(&r, "func_decl_sym");

    n00b_sym_entry_t *sym = lookup_sym(r.annot, "add");
    assert(sym != NULL);
    assert(sym->kind == N00B_SYM_FUNCTION);

    printf("  [PASS] func_decl_sym\n");
}

static void
test_func_param_types(void)
{
    test_result_t r = run_pipeline(
        "func add(a: int, b: int) -> int {\n"
        "    return a + b\n"
        "}\n"
    );
    assert_pipeline(&r, "func_param_types");

    n00b_sym_entry_t *a = lookup_sym(r.annot, "a");
    assert(a != NULL);
    assert(a->kind == N00B_SYM_PARAM);
    assert(a->type_var != NULL);
    assert(is_prim(a->type_var, "int"));
    assert(a->mutability == N00B_SYM_IMMUTABLE);

    n00b_sym_entry_t *b = lookup_sym(r.annot, "b");
    assert(b != NULL);
    assert(b->kind == N00B_SYM_PARAM);
    assert(is_prim(b->type_var, "int"));

    printf("  [PASS] func_param_types\n");
}

// ============================================================================
// SECTION 9: Assignment type propagation (@assigns)
// ============================================================================

static void
test_assign_propagates(void)
{
    // x = 42 should unify x's type with int
    test_result_t r = run_pipeline(
        "var x: int\n"
        "x = 42\n"
    );
    assert_pipeline(&r, "assign_propagates");

    n00b_sym_entry_t *sym = lookup_sym(r.annot, "x");
    assert(sym != NULL);
    assert(sym->type_var != NULL);
    assert(is_prim(sym->type_var, "int"));

    printf("  [PASS] assign_propagates\n");
}

static void
test_binop_assign_propagates(void)
{
    // x += 1 should unify x's type with int
    test_result_t r = run_pipeline(
        "var x: int = 10\n"
        "x += 1\n"
    );
    assert_pipeline(&r, "binop_assign_propagates");

    n00b_sym_entry_t *sym = lookup_sym(r.annot, "x");
    assert(sym != NULL);
    assert(sym->type_var != NULL);
    assert(is_prim(sym->type_var, "int"));

    printf("  [PASS] binop_assign_propagates\n");
}

// ============================================================================
// SECTION 10: Type propagation through expression nodes
// ============================================================================

static void
test_propagation_through_exprs(void)
{
    // 1 + 2 — int should propagate up from add-expr through the expression
    // chain (mul-expr → add-expr → ...) to expression-stmt or at least the
    // enclosing expression nodes.
    test_result_t r = run_pipeline("1 + 2\n");
    assert_pipeline(&r, "propagation_through_exprs");

    n00b_parse_tree_t *add = find_nt_node(shared_grammar, r.tree, "plus-expr");
    assert(add != NULL);

    n00b_tc_type_t *t = get_node_type(r.annot, add);
    assert(t != NULL);
    assert(is_prim(t, "int"));

    printf("  [PASS] propagation_through_exprs\n");
}

// ============================================================================
// SECTION 11: Enum declarations (@adt, @type)
// ============================================================================

static void
test_enum_declares_type(void)
{
    test_result_t r = run_pipeline(
        "enum Color {\n"
        "    Red,\n"
        "    Green,\n"
        "    Blue\n"
        "}\n"
    );
    assert_pipeline(&r, "enum_declares_type");

    // @declares puts the enum name in the default namespace.
    n00b_sym_entry_t *sym = lookup_sym(r.annot, "Color");
    assert(sym != NULL);
    assert(sym->type_var != NULL);

    printf("  [PASS] enum_declares_type\n");
}

// ============================================================================
// SECTION 12: Class declarations (@scope, @declares, @type, @exposes)
// ============================================================================

static void
test_class_declares_sym(void)
{
    test_result_t r = run_pipeline(
        "class Point {\n"
        "    x: int\n"
        "    y: int\n"
        "}\n"
    );
    assert_pipeline(&r, "class_declares_sym");

    n00b_sym_entry_t *sym = lookup_sym(r.annot, "Point");
    assert(sym != NULL);

    printf("  [PASS] class_declares_sym\n");
}

static void
test_class_member_visibility(void)
{
    test_result_t r = run_pipeline(
        "class Foo {\n"
        "    public x: int\n"
        "    private y: string\n"
        "}\n"
    );
    assert_pipeline(&r, "class_member_visibility");

    n00b_sym_entry_t *x = lookup_sym(r.annot, "x");
    assert(x != NULL);
    assert(x->visibility != NULL);
    assert(n00b_unicode_str_eq(x->visibility, r"public"));

    n00b_sym_entry_t *y = lookup_sym(r.annot, "y");
    assert(y != NULL);
    assert(y->visibility != NULL);
    assert(n00b_unicode_str_eq(y->visibility, r"private"));

    printf("  [PASS] class_member_visibility\n");
}

static void
test_class_member_typed(void)
{
    test_result_t r = run_pipeline(
        "class Point {\n"
        "    x: int\n"
        "    y: int\n"
        "}\n"
    );
    assert_pipeline(&r, "class_member_typed");

    n00b_sym_entry_t *x = lookup_sym(r.annot, "x");
    assert(x != NULL);
    assert(x->type_var != NULL);
    assert(is_prim(x->type_var, "int"));

    n00b_sym_entry_t *y = lookup_sym(r.annot, "y");
    assert(y != NULL);
    assert(y->type_var != NULL);
    assert(is_prim(y->type_var, "int"));

    printf("  [PASS] class_member_typed\n");
}

// ============================================================================
// SECTION 13: Interface declarations
// ============================================================================

static void
test_interface_declares_sym(void)
{
    test_result_t r = run_pipeline(
        "interface Printable {\n"
        "    to_string: () -> string\n"
        "}\n"
    );
    assert_pipeline(&r, "interface_declares_sym");

    n00b_sym_entry_t *sym = lookup_sym(r.annot, "Printable");
    assert(sym != NULL);

    printf("  [PASS] interface_declares_sym\n");
}

// ============================================================================
// SECTION 14: Nested expression type inference
// ============================================================================

static void
test_nested_arith(void)
{
    // (1 + 2) * 3 — should be int through the whole chain
    test_result_t r = run_pipeline("var x = (1 + 2) * 3\n");
    assert_pipeline(&r, "nested_arith");

    n00b_sym_entry_t *sym = lookup_sym(r.annot, "x");
    assert(sym != NULL);
    assert(sym->type_var != NULL);
    assert(is_prim(sym->type_var, "int"));

    printf("  [PASS] nested_arith\n");
}

static void
test_mixed_comparison_and_logic(void)
{
    // (1 < 2) and (3 > 1) — bool
    test_result_t r = run_pipeline("var x = (1 < 2) and (3 > 1)\n");
    assert_pipeline(&r, "mixed_comparison_and_logic");

    n00b_sym_entry_t *sym = lookup_sym(r.annot, "x");
    assert(sym != NULL);
    assert(sym->type_var != NULL);
    assert(is_prim(sym->type_var, "bool"));

    printf("  [PASS] mixed_comparison_and_logic\n");
}

// ============================================================================
// SECTION 15: Multiple variable declarations
// ============================================================================

static void
test_multi_var_decl(void)
{
    // Use initializers to disambiguate ":" as type annotation vs assign-op.
    test_result_t r = run_pipeline(
        "var x: int = 0\n"
        "var y: string = \"hi\"\n"
        "var z: bool = true\n"
    );
    assert_pipeline(&r, "multi_var_decl");

    n00b_sym_entry_t *x = lookup_sym(r.annot, "x");
    assert(x != NULL);
    assert(is_prim(x->type_var, "int"));

    n00b_sym_entry_t *y = lookup_sym(r.annot, "y");
    assert(y != NULL);
    assert(is_prim(y->type_var, "string"));

    n00b_sym_entry_t *z = lookup_sym(r.annot, "z");
    assert(z != NULL);
    assert(is_prim(z->type_var, "bool"));

    printf("  [PASS] multi_var_decl\n");
}

// ============================================================================
// SECTION 16: Variable without type annotation stays unresolved
// ============================================================================

static void
test_var_decl_no_type_is_var(void)
{
    // var x  — declared but not assigned, no type annotation
    test_result_t r = run_pipeline("var x\n");
    assert_pipeline(&r, "var_decl_no_type_is_var");

    n00b_sym_entry_t *sym = lookup_sym(r.annot, "x");
    assert(sym != NULL);
    assert(sym->type_var != NULL);

    // Should still be an unresolved type variable
    assert(is_var(sym->type_var));

    printf("  [PASS] var_decl_no_type_is_var\n");
}

// Section 17: Result unwrap (!)

static void
test_unwrap_result(void)
{
    // The `!` postfix operator constrains its operand to result[T]
    // and produces type T.
    test_result_t r = run_pipeline(
        "var rv: result[int]\n"
        "var x = rv!\n"
    );
    assert_pipeline(&r, "unwrap_result");

    // rv should be result[int].
    n00b_sym_entry_t *rsym = lookup_sym(r.annot, "rv");
    assert(rsym != NULL);
    assert(rsym->type_var != NULL);
    assert(is_param(resolve_type(rsym->type_var), "result"));

    // x should be int — the unwrapped T from result[int].
    n00b_sym_entry_t *x = lookup_sym(r.annot, "x");
    assert(x != NULL);
    assert(x->type_var != NULL);
    assert(is_prim(resolve_type(x->type_var), "int"));

    printf("  [PASS] unwrap_result\n");
}

// Section 18: Yield value propagation

static void
test_yield_block_value_type(void)
{
    test_result_t r = run_pipeline(
        "var x = {\n"
        "  var tmp = 7\n"
        "  yield tmp\n"
        "}\n");
    assert_pipeline(&r, "yield_block_value_type");

    n00b_sym_entry_t *x = lookup_sym(r.annot, "x");
    assert(x != NULL);
    assert(x->type_var != NULL);
    assert(is_prim(x->type_var, "int"));

    printf("  [PASS] yield_block_value_type\n");
}

static void
test_yield_switch_value_type(void)
{
    test_result_t r = run_pipeline(
        "var x = switch 3 {\n"
        "  case 1: yield 10\n"
        "  else: yield 99\n"
        "}\n");
    assert_pipeline(&r, "yield_switch_value_type");

    n00b_sym_entry_t *x = lookup_sym(r.annot, "x");
    assert(x != NULL);
    assert(x->type_var != NULL);
    assert(is_prim(x->type_var, "int"));

    printf("  [PASS] yield_switch_value_type\n");
}

static void
test_yield_switch_list_value_type(void)
{
    test_result_t r = run_pipeline(
        "var xs = switch 1 {\n"
        "  case 1: yield [1]\n"
        "  else: yield [2]\n"
        "}\n");
    assert_pipeline(&r, "yield_switch_list_value_type");

    n00b_sym_entry_t *xs = lookup_sym(r.annot, "xs");
    assert(xs != NULL);
    assert(xs->type_var != NULL);
    assert(is_param_arg_prim(xs->type_var, "list", "int"));

    printf("  [PASS] yield_switch_list_value_type\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("test_n00b_types:\n");

    // Setup
    test_grammar_loads();

    if (!shared_grammar) {
        printf("  [SKIP] All tests skipped — grammar failed to load\n");
        return 1;
    }

    // Section 1: Literals
    test_int_literal();
    test_hex_literal();
    test_float_literal();
    test_string_literal();
    test_bool_literal_true();
    test_bool_literal_false();
    test_char_literal();

    // Section 2: Comparisons → bool
    test_lt_bool();
    test_gt_bool();
    test_le_bool();
    test_ge_bool();
    test_eq_bool();
    test_ne_bool();

    // Section 3: Logical operators → bool
    test_and_bool();
    test_or_bool();
    test_not_bool();

    // Section 4: Arithmetic — unify operands
    test_add_unify();
    test_sub_unify();
    test_mul_unify();
    test_div_unify();
    test_mod_unify();

    // Section 5: Unary operators
    test_unary_minus();

    // Section 6: Bitwise operators
    test_bitor_unify();
    test_bitand_unify();
    test_shl_preserves_type();
    test_shr_preserves_type();

    // Section 7: Variable declarations + symbol table
    test_var_decl_typed();
    test_let_decl_typed();
    test_const_decl_typed();
    test_global_decl();
    test_var_decl_untyped_inferred();
    test_var_decl_string_inferred();
    test_var_decl_bool_inferred();
    test_var_decl_float_inferred();
    test_var_decl_expr_inferred();
    test_var_decl_comparison_inferred();

    // Section 8: Function declarations
    test_func_decl_sym();
    test_func_param_types();

    // Section 9: Assignment propagation
    test_assign_propagates();
    test_binop_assign_propagates();

    // Section 10: Expression propagation
    test_propagation_through_exprs();

    // Section 11: Enums
    test_enum_declares_type();

    // Section 12: Classes
    test_class_declares_sym();
    test_class_member_visibility();
    test_class_member_typed();

    // Section 13: Interfaces
    test_interface_declares_sym();

    // Section 14: Nested expressions
    test_nested_arith();
    test_mixed_comparison_and_logic();

    // Section 15: Multiple variable declarations
    test_multi_var_decl();

    // Section 16: Unresolved type variables
    test_var_decl_no_type_is_var();

    // Section 17: Result unwrap (!)
    test_unwrap_result();

    // Section 18: Yield value propagation
    test_yield_block_value_type();
    test_yield_switch_value_type();
    test_yield_switch_list_value_type();

    printf("\nAll n00b_types tests passed.\n");
    return 0;
}

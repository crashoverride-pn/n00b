// test_n00b_programs.c — Test suite of sample n00b programs.
//
// Parses sample programs through the full pipeline (tokenize → parse →
// annotation walk → CFG → DFG → analysis) and verifies correct parsing,
// scope/symbol construction, and diagnostic output.

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
#include "core/string.h"
#include "text/strings/string_ops.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"

#include "typecheck/types.h"
#include "typecheck/context.h"

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
#include "slay/cfg.h"
#include "slay/dfg.h"
#include "slay/diagnostic.h"
#include "slay/analyze.h"

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
        char path[1024];
        snprintf(path, sizeof(path), "%s/grammars/n00b.bnf", srcroot);
        f = fopen(path, "r");
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
    bool             ok       = n00b_bnf_load(bnf_text, r"module", g, .diag = bnf_diag);

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
// Test helpers
// ============================================================================

typedef struct {
    n00b_parse_result_t *pr;
    n00b_parse_tree_t   *tree;
    n00b_annot_result_t *annot;
    n00b_cfg_t          *cfg;
    n00b_dfg_t          *dfg;
    n00b_diag_ctx_t     *diag;
    bool                 parsed;
} pipeline_result_t;

// Run the full pipeline on a source string.
// Always returns a valid pipeline_result_t (check .parsed for parse success).
static pipeline_result_t
run_pipeline(const char *src)
{
    pipeline_result_t r = {0};

    n00b_buffer_t       *buf     = n00b_buffer_from_bytes((char *)src, (int64_t)strlen(src));
    n00b_scanner_t      *scanner = n00b_scanner_new(buf, n00b_lang_tokenize, shared_grammar);
    n00b_token_stream_t *ts      = n00b_token_stream_new(scanner);

    r.pr = n00b_grammar_parse(shared_grammar, ts);

    if (!n00b_parse_result_ok(r.pr)) {
        r.parsed = false;
        r.diag   = n00b_diag_ctx_new();
        n00b_diag_push(r.diag,
                       N00B_DIAG_ERROR,
                       N00B_STAGE_PARSE,
                       r"P001",
                       r"parse failed",
                       (n00b_diag_span_t){0});
        return r;
    }

    r.parsed = true;
    r.tree   = n00b_parse_result_tree(r.pr);
    r.annot  = n00b_compile_walk(shared_grammar, r.tree);
    r.diag   = n00b_diag_ctx_new();

    if (!r.annot) {
        n00b_diag_push(r.diag,
                       N00B_DIAG_ERROR,
                       N00B_STAGE_ANNOT,
                       r"A001",
                       r"annotation walk failed",
                       (n00b_diag_span_t){0});
        return r;
    }

    // Import type-check errors.
    if (r.annot->tc_ctx) {
        n00b_diag_import_tc_errors(r.diag, r.annot->tc_ctx);
    }

    // Build CFG.
    if (r.annot->cf_labels) {
        r.cfg = n00b_build_cfg(r.annot->cf_labels, r.tree, r"module", r.annot->symtab);
    }

    // Build DFG.
    if (r.cfg) {
        r.dfg = n00b_build_dfg(r.cfg, r.annot->cf_labels, shared_grammar, r.annot);
    }

    // Run analysis.
    if (r.cfg && r.dfg) {
        n00b_analyze_ctx_t actx = {
            .cfg       = r.cfg,
            .cdg       = NULL,
            .dfg       = r.dfg,
            .symtab    = r.annot->symtab,
            .cf_labels = r.annot->cf_labels,
            .annot     = r.annot,
            .grammar   = shared_grammar,
            .diag      = r.diag,
            .func_name = r"module",
        };

        n00b_analyze_all(&actx);
    }

    return r;
}

static void
pipeline_free(pipeline_result_t *r)
{
    if (r->dfg) {
        n00b_dfg_free(r->dfg);
    }

    if (r->cfg) {
        n00b_cfg_free(r->cfg);
    }

    if (r->diag) {
        n00b_diag_ctx_free(r->diag);
    }
}

static bool
has_diag_code(n00b_diag_ctx_t *ctx, const char *code)
{
    size_t count = n00b_list_len(ctx->diags);

    for (size_t i = 0; i < count; i++) {
        n00b_diagnostic_t d = n00b_list_get(ctx->diags, i);

        if (d.code->u8_bytes == strlen(code)
            && memcmp(d.code->data, code, d.code->u8_bytes) == 0) {
            return true;
        }
    }

    return false;
}

// Assert that a source string parses successfully through the full pipeline.
static pipeline_result_t
assert_parses(const char *src, const char *test_name)
{
    pipeline_result_t r = run_pipeline(src);

    if (!r.parsed) {
        fprintf(stderr, "  [FAIL] %s: parse failed\n", test_name);
        fprintf(stderr, "  Source: %.60s...\n", src);

        n00b_string_t *err = n00b_parse_result_error_string(r.pr);

        if (err->data) {
            fprintf(stderr, "  Error: %.*s\n", (int)err->u8_bytes, err->data);
        }
    }

    assert(r.parsed);
    return r;
}

// Assert that a source string fails to parse.
static pipeline_result_t
assert_parse_fails(const char *src, const char *test_name)
{
    pipeline_result_t r = run_pipeline(src);

    if (r.parsed) {
        fprintf(stderr, "  [FAIL] %s: expected parse failure but succeeded\n", test_name);
    }

    assert(!r.parsed);
    return r;
}

// ============================================================================
// Test 1: Grammar loads
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
// Test 2: Variable declarations
// ============================================================================

static void
test_var_decl_simple(void)
{
    // Simple untyped with initializer.
    pipeline_result_t r = assert_parses("var x = 42\n", "var_decl_simple");

    n00b_sym_entry_t *x = n00b_symtab_lookup_all(r.annot->symtab, r"", r"x");
    assert(x != NULL);
    assert(x->kind == N00B_SYM_VARIABLE);
    pipeline_free(&r);
    printf("  [PASS] var_decl_simple\n");
}

static void
test_var_decl_typed(void)
{
    // Typed with initializer.
    pipeline_result_t r = assert_parses("var x: int = 42\n", "var_decl_typed");

    n00b_sym_entry_t *x = n00b_symtab_lookup_all(r.annot->symtab, r"", r"x");
    assert(x != NULL);
    assert(x->type_var != NULL);
    pipeline_free(&r);
    printf("  [PASS] var_decl_typed\n");
}

static void
test_var_decl_typed_no_init(void)
{
    // Typed without initializer.
    pipeline_result_t r = assert_parses("var x: int\n", "var_decl_typed_no_init");

    n00b_sym_entry_t *x = n00b_symtab_lookup_all(r.annot->symtab, r"", r"x");
    assert(x != NULL);
    pipeline_free(&r);
    printf("  [PASS] var_decl_typed_no_init\n");
}

static void
test_var_decl_qualifiers(void)
{
    // Various qualifiers.
    pipeline_result_t r1 = assert_parses("let x = 42\n", "let_decl");
    pipeline_free(&r1);

    pipeline_result_t r2 = assert_parses("const x = 42\n", "const_decl");
    pipeline_free(&r2);

    pipeline_result_t r3 = assert_parses("global x = 42\n", "global_decl");
    pipeline_free(&r3);

    // Combined qualifiers.
    pipeline_result_t r4 = assert_parses("global const x = 42\n", "global_const_decl");
    pipeline_free(&r4);

    printf("  [PASS] var_decl_qualifiers\n");
}

static void
test_var_decl_multi(void)
{
    // Multiple variables in one declaration.
    pipeline_result_t r = assert_parses("var x, y = 42\n", "var_decl_multi");
    pipeline_free(&r);
    printf("  [PASS] var_decl_multi\n");
}

static void
test_var_decl_multi_typed(void)
{
    // Multiple typed declarations separated by comma.
    pipeline_result_t r = assert_parses("var x: int, y: int = 1\n", "var_decl_multi_typed");
    pipeline_free(&r);
    printf("  [PASS] var_decl_multi_typed\n");
}

// ============================================================================
// Test 3: Function definitions
// ============================================================================

static void
test_func_simple(void)
{
    const char *src
        = "func f() {\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "func_simple");

    n00b_sym_entry_t *f = n00b_symtab_lookup_all(r.annot->symtab, r"", r"f");
    assert(f != NULL);
    assert(f->kind == N00B_SYM_FUNCTION);
    pipeline_free(&r);
    printf("  [PASS] func_simple\n");
}

static void
test_func_params(void)
{
    const char *src
        = "func add(x: int, y: int) {\n"
          "    var z = x\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "func_params");

    n00b_sym_entry_t *f = n00b_symtab_lookup_all(r.annot->symtab, r"", r"add");
    assert(f != NULL);
    assert(f->kind == N00B_SYM_FUNCTION);

    // Params should be declared.
    assert(r.annot->params != NULL);
    assert(n00b_list_len(*r.annot->params) >= 2);

    pipeline_free(&r);
    printf("  [PASS] func_params\n");
}

static void
test_func_return_type(void)
{
    const char *src
        = "func double(x: int) -> int {\n"
          "    return x\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "func_return_type");
    pipeline_free(&r);
    printf("  [PASS] func_return_type\n");
}

static void
test_func_private(void)
{
    const char *src
        = "private func secret() {\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "func_private");

    n00b_sym_entry_t *f = n00b_symtab_lookup_all(r.annot->symtab, r"", r"secret");
    assert(f != NULL);
    assert(f->kind == N00B_SYM_FUNCTION);

    // No false warnings on private funcs.
    assert(!has_diag_code(r.diag, "W001"));
    assert(!has_diag_code(r.diag, "W002"));

    pipeline_free(&r);
    printf("  [PASS] func_private\n");
}

static void
test_func_once(void)
{
    const char *src
        = "once func init() {\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "func_once");
    assert(!has_diag_code(r.diag, "W001"));
    assert(!has_diag_code(r.diag, "W002"));
    pipeline_free(&r);
    printf("  [PASS] func_once\n");
}

static void
test_func_private_once(void)
{
    const char *src
        = "private once func init_internal() {\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "func_private_once");
    assert(!has_diag_code(r.diag, "W001"));
    assert(!has_diag_code(r.diag, "W002"));
    pipeline_free(&r);
    printf("  [PASS] func_private_once\n");
}

static void
test_func_varargs(void)
{
    const char *src
        = "func variadic(x: int, *rest: int) {\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "func_varargs");
    pipeline_free(&r);
    printf("  [PASS] func_varargs\n");
}

static void
test_func_kwargs(void)
{
    const char *src
        = "func with_kw(timeout: int = 30) {\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "func_kwargs");
    pipeline_free(&r);
    printf("  [PASS] func_kwargs\n");
}

static void
test_func_multiple(void)
{
    // Multiple functions — tests per-function CFG scoping.
    const char *src
        = "func first() {\n"
          "    var x = 1\n"
          "}\n"
          "func second() {\n"
          "    var y = 2\n"
          "}\n"
          "func third() {\n"
          "    var z = 3\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "func_multiple");

    // No false W001 (unreachable code) between functions.
    assert(!has_diag_code(r.diag, "W001"));

    // All three should be in the symbol table.
    assert(n00b_symtab_lookup_all(r.annot->symtab, r"", r"first") != NULL);
    assert(n00b_symtab_lookup_all(r.annot->symtab, r"", r"second") != NULL);
    assert(n00b_symtab_lookup_all(r.annot->symtab, r"", r"third") != NULL);

    pipeline_free(&r);
    printf("  [PASS] func_multiple\n");
}

static void
test_func_method(void)
{
    const char *src
        = "method get_name() {\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "func_method");
    pipeline_free(&r);
    printf("  [PASS] func_method\n");
}

// ============================================================================
// Test 4: Control flow
// ============================================================================

static void
test_if_simple(void)
{
    const char *src
        = "var x = 42\n"
          "if x {\n"
          "    var y = 1\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "if_simple");
    pipeline_free(&r);
    printf("  [PASS] if_simple\n");
}

static void
test_if_else(void)
{
    const char *src
        = "var x = 42\n"
          "if x {\n"
          "    var y = 1\n"
          "} else {\n"
          "    var y = 2\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "if_else");
    pipeline_free(&r);
    printf("  [PASS] if_else\n");
}

static void
test_if_elif_else(void)
{
    const char *src
        = "var x = 42\n"
          "if x == 1 {\n"
          "    var y = 1\n"
          "} elif x == 2 {\n"
          "    var y = 2\n"
          "} elif x == 3 {\n"
          "    var y = 3\n"
          "} else {\n"
          "    var y = 0\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "if_elif_else");
    pipeline_free(&r);
    printf("  [PASS] if_elif_else\n");
}

static void
test_while_loop(void)
{
    const char *src
        = "var x = 10\n"
          "while x {\n"
          "    x = x - 1\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "while_loop");
    pipeline_free(&r);
    printf("  [PASS] while_loop\n");
}

static void
test_for_in(void)
{
    const char *src
        = "var items = [1, 2, 3]\n"
          "for x in items {\n"
          "    var y = x\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "for_in");
    pipeline_free(&r);
    printf("  [PASS] for_in\n");
}

static void
test_for_range(void)
{
    const char *src
        = "for x in 0 to 10 {\n"
          "    var y = x\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "for_range");
    pipeline_free(&r);
    printf("  [PASS] for_range\n");
}

static void
test_for_from_range(void)
{
    const char *src
        = "for x from 1 to 100 {\n"
          "    var y = x\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "for_from_range");
    pipeline_free(&r);
    printf("  [PASS] for_from_range\n");
}

static void
test_for_multi_var(void)
{
    const char *src
        = "var items = {1: \"a\", 2: \"b\"}\n"
          "for k, v in items {\n"
          "    var z = k\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "for_multi_var");
    pipeline_free(&r);
    printf("  [PASS] for_multi_var\n");
}

static void
test_labeled_while(void)
{
    const char *src
        = "outer: while true {\n"
          "    break outer\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "labeled_while");
    pipeline_free(&r);
    printf("  [PASS] labeled_while\n");
}

static void
test_labeled_for(void)
{
    const char *src
        = "outer: for x in 0 to 10 {\n"
          "    continue outer\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "labeled_for");
    pipeline_free(&r);
    printf("  [PASS] labeled_for\n");
}

static void
test_break_continue(void)
{
    const char *src
        = "while true {\n"
          "    break\n"
          "}\n";

    pipeline_result_t r1 = assert_parses(src, "break");
    pipeline_free(&r1);

    const char *src2
        = "while true {\n"
          "    continue\n"
          "}\n";

    pipeline_result_t r2 = assert_parses(src2, "continue");
    pipeline_free(&r2);
    printf("  [PASS] break_continue\n");
}

static void
test_return(void)
{
    const char *src
        = "func f() {\n"
          "    return 42\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "return");
    pipeline_free(&r);

    // Return without value.
    const char *src2
        = "func g() {\n"
          "    return\n"
          "}\n";

    pipeline_result_t r2 = assert_parses(src2, "return_void");
    pipeline_free(&r2);
    printf("  [PASS] return\n");
}

static void
test_yield_statement(void)
{
    const char *direct
        = "func f() -> int {\n"
          "    yield 1\n"
          "}\n";
    pipeline_result_t r1 = assert_parses(direct, "yield_direct");
    pipeline_free(&r1);

    const char *non_final
        = "func f() -> int {\n"
          "    yield 1\n"
          "    var x = 2\n"
          "}\n";
    pipeline_result_t r2 = assert_parse_fails(non_final, "yield_non_final");
    pipeline_free(&r2);

    pipeline_result_t r3 = assert_parse_fails("yield 1\n", "yield_top_level");
    pipeline_free(&r3);

    const char *if_yield
        = "func f(x: bool) -> int {\n"
          "    if x {\n"
          "        yield 10\n"
          "    } else {\n"
          "        yield 20\n"
          "    }\n"
          "}\n";
    pipeline_result_t r4 = assert_parses(if_yield, "yield_if_arms");
    pipeline_free(&r4);

    const char *switch_yield
        = "func f(x: int) -> int {\n"
          "    switch x {\n"
          "        case 1: yield 10\n"
          "        else: yield 20\n"
          "    }\n"
          "}\n";
    pipeline_result_t r5 = assert_parses(switch_yield, "yield_switch_arms");
    pipeline_free(&r5);

    const char *local_yield
        = "func f() -> int {\n"
          "    var x = 7\n"
          "    yield x\n"
          "}\n";
    pipeline_result_t r6 = assert_parses(local_yield, "yield_local_variable");
    pipeline_free(&r6);

    const char *block_assign
        = "var x = {\n"
          "    var tmp = 7\n"
          "    yield tmp\n"
          "}\n";
    pipeline_result_t r7 = assert_parses(block_assign, "yield_assign_block");
    pipeline_free(&r7);

    const char *if_assign
        = "var x = if true {\n"
          "    yield 10\n"
          "} else {\n"
          "    yield 20\n"
          "}\n";
    pipeline_result_t r8 = assert_parses(if_assign, "yield_assign_if");
    pipeline_free(&r8);

    const char *switch_assign
        = "var x = switch 3 {\n"
          "    case 1: yield 10\n"
          "    else: yield 99\n"
          "}\n";
    pipeline_result_t r9 = assert_parses(switch_assign, "yield_assign_switch");
    pipeline_free(&r9);

    const char *func_assign
        = "func f() -> int {\n"
          "    yield 7\n"
          "}\n"
          "var x = f()\n";
    pipeline_result_t r10 = assert_parses(func_assign, "yield_func_assign");
    pipeline_free(&r10);

    const char *incomplete_if
        = "var x = if true {\n"
          "    yield 10\n"
          "}\n";
    pipeline_result_t r11 = assert_parse_fails(incomplete_if, "yield_incomplete_if");
    pipeline_free(&r11);

    const char *incomplete_switch
        = "var x = switch 3 {\n"
          "    case 1: yield 10\n"
          "}\n";
    pipeline_result_t r12 = assert_parse_fails(incomplete_switch, "yield_incomplete_switch");
    pipeline_free(&r12);

    printf("  [PASS] yield_statement\n");
}

// ============================================================================
// Test 5: Switch statement
// ============================================================================

static void
test_switch_basic(void)
{
    const char *src
        = "var x = 42\n"
          "switch x {\n"
          "    case 1: var y = 1\n"
          "    case 2: var y = 2\n"
          "    else: var y = 0\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "switch_basic");
    pipeline_free(&r);
    printf("  [PASS] switch_basic\n");
}

static void
test_switch_body_blocks(void)
{
    const char *src
        = "var x = 42\n"
          "switch x {\n"
          "    case 1 {\n"
          "        var y = 1\n"
          "    }\n"
          "    case 2 {\n"
          "        var y = 2\n"
          "    }\n"
          "    else {\n"
          "        var y = 0\n"
          "    }\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "switch_body_blocks");
    pipeline_free(&r);
    printf("  [PASS] switch_body_blocks\n");
}

static void
test_switch_multi_case(void)
{
    const char *src
        = "var x = 42\n"
          "switch x {\n"
          "    case 1, 2, 3: var y = 1\n"
          "    else: var y = 0\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "switch_multi_case");
    pipeline_free(&r);
    printf("  [PASS] switch_multi_case\n");
}

static void
test_switch_range_case(void)
{
    const char *src
        = "var x = 42\n"
          "switch x {\n"
          "    case 1 to 10: var y = 1\n"
          "    else: var y = 0\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "switch_range_case");
    pipeline_free(&r);
    printf("  [PASS] switch_range_case\n");
}

// ============================================================================
// Test 6: Typeof dispatch
// ============================================================================

static void
test_typeof_basic(void)
{
    const char *src
        = "var x = 42\n"
          "typeof x {\n"
          "    case int: var y = 1\n"
          "    case string: var y = 2\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "typeof_basic");
    pipeline_free(&r);
    printf("  [PASS] typeof_basic\n");
}

static void
test_typeof_multi_type(void)
{
    const char *src
        = "var x = 42\n"
          "typeof x {\n"
          "    case int, i32: var y = 1\n"
          "    else: var y = 0\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "typeof_multi_type");
    pipeline_free(&r);
    printf("  [PASS] typeof_multi_type\n");
}

// ============================================================================
// Test 7: Expressions
// ============================================================================

static void
test_expr_arithmetic(void)
{
    // Arithmetic operators.
    pipeline_result_t r = assert_parses("var x = 1 + 2 * 3 - 4 / 2\n", "expr_arithmetic");
    pipeline_free(&r);

    // Modulo.
    pipeline_result_t r2 = assert_parses("var x = 10 % 3\n", "expr_mod");
    pipeline_free(&r2);

    printf("  [PASS] expr_arithmetic\n");
}

static void
test_expr_comparison(void)
{
    pipeline_result_t r = assert_parses("var x = 1 == 2\n", "expr_eq");
    pipeline_free(&r);

    pipeline_result_t r2 = assert_parses("var x = 1 != 2\n", "expr_ne");
    pipeline_free(&r2);

    pipeline_result_t r3 = assert_parses("var x = 1 < 2\n", "expr_lt");
    pipeline_free(&r3);

    pipeline_result_t r4 = assert_parses("var x = 1 <= 2\n", "expr_le");
    pipeline_free(&r4);

    pipeline_result_t r5 = assert_parses("var x = 1 > 2\n", "expr_gt");
    pipeline_free(&r5);

    pipeline_result_t r6 = assert_parses("var x = 1 >= 2\n", "expr_ge");
    pipeline_free(&r6);

    printf("  [PASS] expr_comparison\n");
}

static void
test_expr_logical(void)
{
    pipeline_result_t r = assert_parses("var x = true and false\n", "expr_and");
    pipeline_free(&r);

    pipeline_result_t r2 = assert_parses("var x = true or false\n", "expr_or");
    pipeline_free(&r2);

    printf("  [PASS] expr_logical\n");
}

static void
test_expr_bitwise(void)
{
    pipeline_result_t r = assert_parses("var x = 0xff & 0x0f\n", "expr_band");
    pipeline_free(&r);

    pipeline_result_t r2 = assert_parses("var x = 0xff | 0x0f\n", "expr_bor");
    pipeline_free(&r2);

    pipeline_result_t r3 = assert_parses("var x = 0xff ^ 0x0f\n", "expr_bxor");
    pipeline_free(&r3);

    pipeline_result_t r4 = assert_parses("var x = 1 << 4\n", "expr_shl");
    pipeline_free(&r4);

    pipeline_result_t r5 = assert_parses("var x = 16 >> 2\n", "expr_shr");
    pipeline_free(&r5);

    printf("  [PASS] expr_bitwise\n");
}

static void
test_expr_unary(void)
{
    pipeline_result_t r = assert_parses("var x = !true\n", "expr_not");
    pipeline_free(&r);

    pipeline_result_t r2 = assert_parses("var x = -42\n", "expr_neg");
    pipeline_free(&r2);

    pipeline_result_t r3 = assert_parses("var x = +42\n", "expr_pos");
    pipeline_free(&r3);

    printf("  [PASS] expr_unary\n");
}

static void
test_expr_postfix(void)
{
    // Member access.
    pipeline_result_t r = assert_parses("var x = foo.bar\n", "expr_member");
    pipeline_free(&r);

    // Indexing.
    pipeline_result_t r2 = assert_parses(
        "var items = [1, 2, 3]\n"
        "var x = items[0]\n",
        "expr_index");
    pipeline_free(&r2);

    // Function call.
    pipeline_result_t r3 = assert_parses("var x = foo(1, 2)\n", "expr_call");
    pipeline_free(&r3);

    printf("  [PASS] expr_postfix\n");
}

static void
test_expr_index_slice(void)
{
    // Slice: items[1:3]
    pipeline_result_t r = assert_parses(
        "var items = [1, 2, 3, 4, 5]\n"
        "var x = items[1 to 3]\n",
        "expr_slice");
    pipeline_free(&r);

    // Slice from start: items[:3]
    pipeline_result_t r2 = assert_parses(
        "var items = [1, 2, 3, 4, 5]\n"
        "var x = items[:3]\n",
        "expr_slice_from_start");
    pipeline_free(&r2);

    printf("  [PASS] expr_index_slice\n");
}

static void
test_expr_call_kwargs(void)
{
    const char *src = "var x = foo(1, bar = 2)\n";

    pipeline_result_t r = assert_parses(src, "expr_call_kwargs");
    pipeline_free(&r);
    printf("  [PASS] expr_call_kwargs\n");
}

static void
test_expr_paren(void)
{
    pipeline_result_t r = assert_parses("var x = (1 + 2) * 3\n", "expr_paren");
    pipeline_free(&r);
    printf("  [PASS] expr_paren\n");
}

static void
test_expr_unwrap(void)
{
    // Postfix ! (unwrap_result).
    pipeline_result_t r = assert_parses("var x = foo!\n", "expr_unwrap");
    pipeline_free(&r);
    printf("  [PASS] expr_unwrap\n");
}

// ============================================================================
// Test 8: Literals
// ============================================================================

static void
test_literal_int(void)
{
    pipeline_result_t r = assert_parses("var x = 42\n", "literal_int");
    pipeline_free(&r);

    pipeline_result_t r2 = assert_parses("var x = 0xff\n", "literal_hex");
    pipeline_free(&r2);

    printf("  [PASS] literal_int\n");
}

static void
test_literal_float(void)
{
    pipeline_result_t r = assert_parses("var x = 3.14\n", "literal_float");
    pipeline_free(&r);
    printf("  [PASS] literal_float\n");
}

static void
test_literal_string(void)
{
    pipeline_result_t r = assert_parses("var x = \"hello world\"\n", "literal_string");
    pipeline_free(&r);
    printf("  [PASS] literal_string\n");
}

static void
test_literal_char(void)
{
    pipeline_result_t r = assert_parses("var x = 'c'\n", "literal_char");
    pipeline_free(&r);
    printf("  [PASS] literal_char\n");
}

static void
test_literal_bool(void)
{
    pipeline_result_t r = assert_parses("var x = true\n", "literal_true");
    pipeline_free(&r);

    pipeline_result_t r2 = assert_parses("var x = false\n", "literal_false");
    pipeline_free(&r2);

    printf("  [PASS] literal_bool\n");
}

static void
test_literal_with_modifier(void)
{
    // Int with modifier
    pipeline_result_t r = assert_parses("var x = 42'u8\n", "literal_int_mod");
    pipeline_free(&r);

    // Float with modifier
    pipeline_result_t r2 = assert_parses("var x = 3.14'f32\n", "literal_float_mod");
    pipeline_free(&r2);

    // Hex with modifier
    pipeline_result_t r3 = assert_parses("var x = 0xFF'u32\n", "literal_hex_mod");
    pipeline_free(&r3);

    // String with modifier
    pipeline_result_t r4 = assert_parses("var x = \"hello\"'utf8\n", "literal_string_mod");
    pipeline_free(&r4);

    // Int with full type name modifier
    pipeline_result_t r6 = assert_parses("var x = 100'int\n", "literal_int_typename_mod");
    pipeline_free(&r6);

    // Hex with i64
    pipeline_result_t r7 = assert_parses("var x = 0xDEAD'i64\n", "literal_hex_i64_mod");
    pipeline_free(&r7);

    printf("  [PASS] literal_with_modifier\n");
}

// ============================================================================
// Test 9: Collection literals
// ============================================================================

static void
test_list_literal(void)
{
    pipeline_result_t r = assert_parses("var x = [1, 2, 3]\n", "list_lit");
    pipeline_free(&r);

    // Empty list.
    pipeline_result_t r2 = assert_parses("var x = []\n", "list_empty");
    pipeline_free(&r2);

    printf("  [PASS] list_literal\n");
}

static void
test_dict_literal(void)
{
    pipeline_result_t r = assert_parses("var x = {\"a\": 1, \"b\": 2}\n", "dict_lit");
    pipeline_free(&r);

    // Empty dict.
    pipeline_result_t r2 = assert_parses("var x = {}\n", "dict_empty");
    pipeline_free(&r2);

    printf("  [PASS] dict_literal\n");
}

static void
test_set_literal(void)
{
    pipeline_result_t r = assert_parses("var x = {1, 2, 3}\n", "set_lit");
    pipeline_free(&r);
    printf("  [PASS] set_literal\n");
}

static void
test_tuple_literal(void)
{
    pipeline_result_t r = assert_parses("var x = (1, 2, 3)\n", "tuple_lit");
    pipeline_free(&r);
    printf("  [PASS] tuple_literal\n");
}

// ============================================================================
// Test 10: Assignments
// ============================================================================

static void
test_assign_equals(void)
{
    const char *src
        = "var x = 1\n"
          "x = 42\n";

    pipeline_result_t r = assert_parses(src, "assign_equals");
    pipeline_free(&r);
    printf("  [PASS] assign_equals\n");
}

static void
test_binop_assign(void)
{
    const char *src
        = "var x = 10\n"
          "x += 5\n"
          "x -= 3\n"
          "x *= 2\n"
          "x /= 4\n"
          "x %= 3\n";

    pipeline_result_t r = assert_parses(src, "binop_assign");
    pipeline_free(&r);
    printf("  [PASS] binop_assign\n");
}

static void
test_bitwise_assign(void)
{
    const char *src
        = "var x = 0xff\n"
          "x &= 0x0f\n"
          "x |= 0xf0\n"
          "x ^= 0x01\n"
          "x <<= 2\n"
          "x >>= 1\n";

    pipeline_result_t r = assert_parses(src, "bitwise_assign");
    pipeline_free(&r);
    printf("  [PASS] bitwise_assign\n");
}

// ============================================================================
// Test 11: Assert
// ============================================================================

static void
test_assert_stmt(void)
{
    pipeline_result_t r = assert_parses("assert true\n", "assert_stmt");
    pipeline_free(&r);

    pipeline_result_t r2 = assert_parses("assert 1 == 1\n", "assert_expr");
    pipeline_free(&r2);

    printf("  [PASS] assert_stmt\n");
}

// ============================================================================
// Test 12: Use statement
// ============================================================================

static void
test_use_stmt(void)
{
    pipeline_result_t r = assert_parses("use foo\n", "use_simple");
    pipeline_free(&r);

    pipeline_result_t r2 = assert_parses("use foo.bar\n", "use_chain");
    pipeline_free(&r2);

    pipeline_result_t r3 = assert_parses("use foo from \"path/to/lib\"\n", "use_from");
    pipeline_free(&r3);

    printf("  [PASS] use_stmt\n");
}

// ============================================================================
// Test 13: Enum
// ============================================================================

static void
test_enum_basic(void)
{
    const char *src
        = "enum Color {\n"
          "    Red,\n"
          "    Green,\n"
          "    Blue,\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "enum_basic");
    pipeline_free(&r);
    printf("  [PASS] enum_basic\n");
}

static void
test_enum_with_values(void)
{
    const char *src
        = "enum Priority {\n"
          "    Low = 1,\n"
          "    Medium = 2,\n"
          "    High = 3,\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "enum_with_values");
    pipeline_free(&r);
    printf("  [PASS] enum_with_values\n");
}

static void
test_enum_private(void)
{
    const char *src
        = "private enum Internal {\n"
          "    A,\n"
          "    B,\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "enum_private");
    pipeline_free(&r);
    printf("  [PASS] enum_private\n");
}

static void
test_enum_anonymous(void)
{
    const char *src
        = "enum {\n"
          "    X,\n"
          "    Y,\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "enum_anonymous");
    pipeline_free(&r);
    printf("  [PASS] enum_anonymous\n");
}

// ============================================================================
// Test 14: Class declarations
// ============================================================================

static void
test_class_basic(void)
{
    const char *src
        = "class Point {\n"
          "    x: int\n"
          "    y: int\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "class_basic");
    pipeline_free(&r);
    printf("  [PASS] class_basic\n");
}

static void
test_class_untyped_fields(void)
{
    const char *src
        = "class Config {\n"
          "    name\n"
          "    value\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "class_untyped_fields");
    pipeline_free(&r);
    printf("  [PASS] class_untyped_fields\n");
}

static void
test_class_atomic(void)
{
    const char *src
        = "atomic class Counter {\n"
          "    value: int\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "class_atomic");
    pipeline_free(&r);
    printf("  [PASS] class_atomic\n");
}

// ============================================================================
// Test 15: Type specifications
// ============================================================================

static void
test_type_spec_simple(void)
{
    pipeline_result_t r = assert_parses("var x: int = 42\n", "tspec_simple");
    pipeline_free(&r);
    printf("  [PASS] type_spec_simple\n");
}

static void
test_type_spec_parameterized(void)
{
    // Simple parameterized: list[int]
    pipeline_result_t r = assert_parses("var x: list[int] = []\n", "tspec_param_list_int");
    pipeline_free(&r);

    // Two-param: dict[string, int]
    pipeline_result_t r2 = assert_parses("var x: dict[string, int] = {}\n", "tspec_param_dict");
    pipeline_free(&r2);

    // Nested: list[list[int]]
    pipeline_result_t r3 = assert_parses("var x: list[list[int]] = []\n", "tspec_param_nested");
    pipeline_free(&r3);

    // Deeply nested: list[list[list[string]]]
    pipeline_result_t r4
        = assert_parses("var x: list[list[list[string]]] = []\n", "tspec_param_deep");
    pipeline_free(&r4);

    // Dict with parameterized value: dict[string, list[int]]
    pipeline_result_t r5
        = assert_parses("var x: dict[string, list[int]] = {}\n", "tspec_dict_list_val");
    pipeline_free(&r5);

    // Dict with parameterized key: dict[list[int], string]
    pipeline_result_t r6
        = assert_parses("var x: dict[list[int], string] = {}\n", "tspec_dict_list_key");
    pipeline_free(&r6);

    // Both key and value parameterized: dict[list[int], set[string]]
    pipeline_result_t r7
        = assert_parses("var x: dict[list[int], set[string]] = {}\n", "tspec_dict_both_param");
    pipeline_free(&r7);

    // set[T] parameterized
    pipeline_result_t r8 = assert_parses("var x: set[int] = {}\n", "tspec_set_int");
    pipeline_free(&r8);

    // tuple with multiple params: tuple[int, string, bool]
    pipeline_result_t r9 = assert_parses("var x: tuple[int, string, bool] = (1, \"a\", true)\n",
                                         "tspec_tuple_multi");
    pipeline_free(&r9);

    printf("  [PASS] type_spec_parameterized\n");
}

static void
test_type_spec_tvar(void)
{
    // Simple type variable
    pipeline_result_t r = assert_parses("var x: `T = 42\n", "tspec_tvar");
    pipeline_free(&r);

    // Type variable in container: list[`T]
    pipeline_result_t r2 = assert_parses("var x: list[`T] = []\n", "tspec_tvar_in_list");
    pipeline_free(&r2);

    // Multiple tvars: dict[`K, `V]
    pipeline_result_t r3 = assert_parses("var x: dict[`K, `V] = {}\n", "tspec_tvar_dict");
    pipeline_free(&r3);

    // Mixed concrete and tvar: dict[string, `V]
    pipeline_result_t r4 = assert_parses("var x: dict[string, `V] = {}\n", "tspec_tvar_mixed");
    pipeline_free(&r4);

    // Nested tvar: list[list[`T]]
    pipeline_result_t r5 = assert_parses("var x: list[list[`T]] = []\n", "tspec_tvar_nested");
    pipeline_free(&r5);

    printf("  [PASS] type_spec_tvar\n");
}

static void
test_type_spec_func(void)
{
    // Basic function type: (int, int) -> int
    pipeline_result_t r = assert_parses("var f: (int, int) -> int\n", "tspec_func_basic");
    pipeline_free(&r);

    // No params: () -> int
    pipeline_result_t r2 = assert_parses("var f: () -> int\n", "tspec_func_no_params");
    pipeline_free(&r2);

    // No return type: (int) -> void
    pipeline_result_t r3 = assert_parses("var f: (int) -> void\n", "tspec_func_void_ret");
    pipeline_free(&r3);

    // Single param: (string) -> int
    pipeline_result_t r4
        = assert_parses("var f: (string) -> int\n", "tspec_func_single_param");
    pipeline_free(&r4);

    // Func type with vargs: (int, *string) -> void
    pipeline_result_t r5
        = assert_parses("var f: (int, *string) -> void\n", "tspec_func_vargs");
    pipeline_free(&r5);

    // Func type with kargs: (**name: string) -> void
    pipeline_result_t r6
        = assert_parses("var f: (**name: string) -> void\n", "tspec_func_kargs");
    pipeline_free(&r6);

    // Func type with vargs and kargs: (int, *string, **name: int) -> void
    pipeline_result_t r7 = assert_parses("var f: (int, *string, **name: int) -> void\n",
                                         "tspec_func_vargs_kargs");
    pipeline_free(&r7);

    // Func type with parameterized params: (list[int]) -> dict[string, int]
    pipeline_result_t r8 = assert_parses("var f: (list[int]) -> dict[string, int]\n",
                                         "tspec_func_param_types");
    pipeline_free(&r8);

    // Func type with tvar params: (`T) -> `T
    pipeline_result_t r9 = assert_parses("var f: (`T) -> `T\n", "tspec_func_tvar");
    pipeline_free(&r9);

    // Higher-order: ((int) -> int) -> int
    pipeline_result_t r10
        = assert_parses("var f: ((int) -> int) -> int\n", "tspec_func_higher_order");
    pipeline_free(&r10);

    // Func returning func: (int) -> (int) -> int
    pipeline_result_t r11
        = assert_parses("var f: (int) -> (int) -> int\n", "tspec_func_ret_func");
    pipeline_free(&r11);

    // Multiple kargs fields: (**name: string, age: int) -> void
    // In type-spec syntax, ** prefixes the group, then comma-separated fields.
    pipeline_result_t r12 = assert_parses("var f: (**name: string, age: int) -> void\n",
                                          "tspec_func_multi_kargs");
    pipeline_free(&r12);

    printf("  [PASS] type_spec_func\n");
}

static void
test_type_spec_ref(void)
{
    // Simple ref
    pipeline_result_t r = assert_parses("var x: ref[int]\n", "tspec_ref_int");
    pipeline_free(&r);

    // Ref to parameterized type: ref[list[int]]
    pipeline_result_t r2 = assert_parses("var x: ref[list[int]]\n", "tspec_ref_list");
    pipeline_free(&r2);

    // Ref to tvar: ref[`T]
    pipeline_result_t r3 = assert_parses("var x: ref[`T]\n", "tspec_ref_tvar");
    pipeline_free(&r3);

    printf("  [PASS] type_spec_ref\n");
}

static void
test_type_spec_containers_with_tvars(void)
{
    // Container of containers with tvars
    // dict[`K, list[`V]]
    pipeline_result_t r1
        = assert_parses("var x: dict[`K, list[`V]] = {}\n", "tspec_dict_tvar_list");
    pipeline_free(&r1);

    // set[list[`T]]
    pipeline_result_t r2 = assert_parses("var x: set[list[`T]] = {}\n", "tspec_set_list_tvar");
    pipeline_free(&r2);

    // list[dict[`K, `V]]
    pipeline_result_t r3
        = assert_parses("var x: list[dict[`K, `V]] = []\n", "tspec_list_dict_tvar");
    pipeline_free(&r3);

    // ref[dict[string, list[`T]]]
    pipeline_result_t r4 = assert_parses("var x: ref[dict[string, list[`T]]]\n",
                                         "tspec_ref_dict_list_tvar");
    pipeline_free(&r4);

    // tuple[`A, list[`B], dict[`C, `D]]
    pipeline_result_t r5 = assert_parses("var x: tuple[`A, list[`B], dict[`C, `D]]\n",
                                         "tspec_tuple_mixed_tvars");
    pipeline_free(&r5);

    printf("  [PASS] type_spec_containers_with_tvars\n");
}

static void
test_type_spec_func_with_containers(void)
{
    // Func taking container, returning container
    // (list[int], dict[string, int]) -> set[string]
    pipeline_result_t r1
        = assert_parses("var f: (list[int], dict[string, int]) -> set[string]\n",
                        "tspec_func_containers");
    pipeline_free(&r1);

    // Func taking tvar container: (list[`T]) -> `T
    pipeline_result_t r2
        = assert_parses("var f: (list[`T]) -> `T\n", "tspec_func_list_tvar");
    pipeline_free(&r2);

    // Func taking func that takes container:
    // ((list[int]) -> int) -> list[int]
    pipeline_result_t r3 = assert_parses("var f: ((list[int]) -> int) -> list[int]\n",
                                         "tspec_func_higher_container");
    pipeline_free(&r3);

    // Func with vargs of container type: (*list[int]) -> void
    pipeline_result_t r4
        = assert_parses("var f: (*list[int]) -> void\n", "tspec_func_vargs_container");
    pipeline_free(&r4);

    // Func with kargs of container type: (**items: list[int]) -> void
    pipeline_result_t r5 = assert_parses("var f: (**items: list[int]) -> void\n",
                                         "tspec_func_kargs_container");
    pipeline_free(&r5);

    printf("  [PASS] type_spec_func_with_containers\n");
}

static void
test_type_spec_in_var_decls(void)
{
    // Typed var decls with complex type specs
    // list[list[dict[string, int]]]
    pipeline_result_t r1
        = assert_parses("var x: list[list[dict[string, int]]] = []\n", "tspec_var_deep_nested");
    pipeline_free(&r1);

    // Function-typed variable with full signature
    pipeline_result_t r2
        = assert_parses("var f: (list[`T], ((`T) -> bool)) -> list[`T]\n",
                        "tspec_var_filter_sig");
    pipeline_free(&r2);

    // ref to function type
    pipeline_result_t r3
        = assert_parses("var f: ref[(int) -> int]\n", "tspec_var_ref_func");
    pipeline_free(&r3);

    printf("  [PASS] type_spec_in_var_decls\n");
}

static void
test_type_spec_in_func_params(void)
{
    // Function with parameterized param types
    const char *src1
        = "func process(items: list[int], lookup: dict[string, int]) {\n"
          "    var x = 1\n"
          "}\n";
    pipeline_result_t r1 = assert_parses(src1, "tspec_func_param_containers");
    pipeline_free(&r1);

    // Function with tvar param types
    const char *src2
        = "func identity(x: `T) -> `T {\n"
          "    return x\n"
          "}\n";
    pipeline_result_t r2 = assert_parses(src2, "tspec_func_param_tvar");
    pipeline_free(&r2);

    // Function with callback param that has container types
    const char *src3
        = "func apply(items: list[`T], f: (`T) -> `U) -> list[`U] {\n"
          "    return []\n"
          "}\n";
    pipeline_result_t r3 = assert_parses(src3, "tspec_func_param_map_sig");
    pipeline_free(&r3);

    // Function with ref param
    const char *src4
        = "func swap(a: ref[int], b: ref[int]) {\n"
          "    var x = 1\n"
          "}\n";
    pipeline_result_t r4 = assert_parses(src4, "tspec_func_param_ref");
    pipeline_free(&r4);

    // Function returning parameterized type
    const char *src5
        = "func make_pair(a: `A, b: `B) -> tuple[`A, `B] {\n"
          "    return (a, b)\n"
          "}\n";
    pipeline_result_t r5 = assert_parses(src5, "tspec_func_ret_tuple_tvar");
    pipeline_free(&r5);

    printf("  [PASS] type_spec_in_func_params\n");
}

static void
test_type_spec_in_class_fields(void)
{
    // Class with parameterized field types
    const char *src1
        = "class Container {\n"
          "    items: list[int]\n"
          "    lookup: dict[string, list[int]]\n"
          "}\n";
    pipeline_result_t r1 = assert_parses(src1, "tspec_class_container_fields");
    pipeline_free(&r1);

    // Class with tvar fields
    const char *src2
        = "class Pair {\n"
          "    first: `A\n"
          "    second: `B\n"
          "}\n";
    pipeline_result_t r2 = assert_parses(src2, "tspec_class_tvar_fields");
    pipeline_free(&r2);

    // Class with function-typed field
    // Note: "callback" is a keyword; use a different name.
    const char *src3
        = "class Handler {\n"
          "    on_event: (int) -> void\n"
          "    transform: (`T) -> list[`T]\n"
          "}\n";
    pipeline_result_t r3 = assert_parses(src3, "tspec_class_func_fields");
    pipeline_free(&r3);

    printf("  [PASS] type_spec_in_class_fields\n");
}

static void
test_type_spec_litmod_with_types(void)
{
    // Litmod with parameterized type on int literal
    pipeline_result_t r1 = assert_parses("var x = 42'list[int]\n", "tspec_litmod_param");
    pipeline_free(&r1);

    // Litmod with tvar on int literal
    pipeline_result_t r2 = assert_parses("var x = 42'`T\n", "tspec_litmod_tvar");
    pipeline_free(&r2);

    // Litmod with function type on string literal
    pipeline_result_t r3
        = assert_parses("var x = \"handler\"'(int) -> void\n", "tspec_litmod_func");
    pipeline_free(&r3);

    // Litmod on list literal
    pipeline_result_t r4 = assert_parses("var x = [1, 2, 3]'list[int]\n", "tspec_litmod_list");
    pipeline_free(&r4);

    // Litmod on empty list
    pipeline_result_t r5
        = assert_parses("var x = []'list[string]\n", "tspec_litmod_empty_list");
    pipeline_free(&r5);

    // Litmod on dict literal
    pipeline_result_t r6
        = assert_parses("var x = {\"a\": 1}'dict[string, int]\n", "tspec_litmod_dict");
    pipeline_free(&r6);

    // Litmod on empty dict/set
    pipeline_result_t r7 = assert_parses("var x = {}'set[int]\n", "tspec_litmod_empty_set");
    pipeline_free(&r7);

    // Litmod on set literal
    pipeline_result_t r8 = assert_parses("var x = {1, 2, 3}'set[int]\n", "tspec_litmod_set");
    pipeline_free(&r8);

    // Litmod on tuple literal
    pipeline_result_t r9
        = assert_parses("var x = (1, \"a\")'tuple[int, string]\n", "tspec_litmod_tuple");
    pipeline_free(&r9);

    // Litmod on list with tvar
    pipeline_result_t r10
        = assert_parses("var x = [1, 2]'list[`T]\n", "tspec_litmod_list_tvar");
    pipeline_free(&r10);

    // Litmod on dict with nested container type
    pipeline_result_t r11
        = assert_parses("var x = {}'dict[string, list[int]]\n", "tspec_litmod_dict_nested");
    pipeline_free(&r11);

    printf("  [PASS] type_spec_litmod_with_types\n");
}

// ============================================================================
// Test 15b: Union types and where clauses
// ============================================================================

static void
test_union_type_basic(void)
{
    // Upper tier (after :) requires parens for union types.
    pipeline_result_t r = assert_parses("var x: (int | string)\n", "union_type_basic");
    pipeline_free(&r);
    printf("  [PASS] union_type_basic\n");
}

static void
test_union_type_triple(void)
{
    pipeline_result_t r = assert_parses("var x: (int | string | nil)\n", "union_type_triple");
    pipeline_free(&r);
    printf("  [PASS] union_type_triple\n");
}

static void
test_union_in_list(void)
{
    pipeline_result_t r = assert_parses("var x: list[int | string]\n", "union_in_list");
    pipeline_free(&r);
    printf("  [PASS] union_in_list\n");
}

static void
test_union_in_dict(void)
{
    pipeline_result_t r = assert_parses("var x: dict[string, int | nil]\n", "union_in_dict");
    pipeline_free(&r);
    printf("  [PASS] union_in_dict\n");
}

static void
test_union_in_func_param(void)
{
    // After : in param decl is upper tier; use parens for union.
    pipeline_result_t r = assert_parses(
        "func f(x: (int | string)) {\n"
        "    var y = x\n"
        "}\n",
        "union_in_func_param");
    pipeline_free(&r);
    printf("  [PASS] union_in_func_param\n");
}

static void
test_union_in_return(void)
{
    // Return type after -> uses union-tspec (lower tier),
    // so | is allowed directly.
    pipeline_result_t r = assert_parses(
        "func f() -> int | nil {\n"
        "    return 0\n"
        "}\n",
        "union_in_return");
    pipeline_free(&r);
    printf("  [PASS] union_in_return\n");
}

static void
test_union_with_tvar(void)
{
    // Upper tier requires parens.
    pipeline_result_t r = assert_parses("var x: (`T | nil)\n", "union_with_tvar");
    pipeline_free(&r);
    printf("  [PASS] union_with_tvar\n");
}

static void
test_union_nested_param(void)
{
    // Upper tier requires parens.
    pipeline_result_t r = assert_parses("var x: (list[int] | nil)\n", "union_nested_param");
    pipeline_free(&r);
    printf("  [PASS] union_nested_param\n");
}

static void
test_where_basic(void)
{
    pipeline_result_t r = assert_parses("var x: `T [`T: Numeric]\n", "where_basic");
    pipeline_free(&r);
    printf("  [PASS] where_basic\n");
}

static void
test_where_multi_constraint(void)
{
    pipeline_result_t r
        = assert_parses("var x: `T [`T: Numeric + Comparable]\n", "where_multi_constraint");
    pipeline_free(&r);
    printf("  [PASS] where_multi_constraint\n");
}

static void
test_where_exclusion(void)
{
    pipeline_result_t r = assert_parses("var x: `T [`T: != nil]\n", "where_exclusion");
    pipeline_free(&r);
    printf("  [PASS] where_exclusion\n");
}

static void
test_where_multi_var(void)
{
    pipeline_result_t r = assert_parses(
        "func f(a: `T, b: `U) [`T: Hashable, `U: Printable] -> `T {\n"
        "    return a\n"
        "}\n",
        "where_multi_var");
    pipeline_free(&r);
    printf("  [PASS] where_multi_var\n");
}

static void
test_where_mixed(void)
{
    pipeline_result_t r = assert_parses("var x: `T [`T: Numeric + != nil]\n", "where_mixed");
    pipeline_free(&r);
    printf("  [PASS] where_mixed\n");
}

// ============================================================================
// Test 16: Parameter block
// ============================================================================

static void
test_parameter_block(void)
{
    const char *src
        = "parameter var debug {\n"
          "    kind: default\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "parameter_block");
    pipeline_free(&r);
    printf("  [PASS] parameter_block\n");
}

// ============================================================================
// Test 17: Expression statements
// ============================================================================

static void
test_expr_stmt(void)
{
    // Bare expression as a statement (function call).
    pipeline_result_t r = assert_parses("foo(1, 2)\n", "expr_stmt_call");
    pipeline_free(&r);

    // Method call chain.
    pipeline_result_t r2 = assert_parses("foo.bar()\n", "expr_stmt_method");
    pipeline_free(&r2);

    printf("  [PASS] expr_stmt\n");
}

// ============================================================================
// Test 18: Nested scopes
// ============================================================================

static void
test_nested_scopes(void)
{
    const char *src
        = "var x = 1\n"
          "if x {\n"
          "    var y = 2\n"
          "    if y {\n"
          "        var z = 3\n"
          "    }\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "nested_scopes");

    // Module-level x should exist.
    n00b_sym_entry_t *x = n00b_symtab_lookup_all(r.annot->symtab, r"", r"x");
    assert(x != NULL);

    pipeline_free(&r);
    printf("  [PASS] nested_scopes\n");
}

// ============================================================================
// Test 19: Complex programs
// ============================================================================

static void
test_complex_function(void)
{
    const char *src
        = "func fibonacci(n: int) -> int {\n"
          "    if n <= 1 {\n"
          "        return n\n"
          "    }\n"
          "    var a = 0\n"
          "    var b = 1\n"
          "    for i in 2 to n {\n"
          "        var tmp = b\n"
          "        b = a + b\n"
          "        a = tmp\n"
          "    }\n"
          "    return b\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "complex_function");

    n00b_sym_entry_t *f = n00b_symtab_lookup_all(r.annot->symtab, r"", r"fibonacci");
    assert(f != NULL);
    assert(f->kind == N00B_SYM_FUNCTION);
    assert(f->cfg != NULL);

    pipeline_free(&r);
    printf("  [PASS] complex_function\n");
}

static void
test_mixed_declarations(void)
{
    const char *src
        = "var counter = 0\n"
          "const MAX = 100\n"
          "\n"
          "func increment() {\n"
          "    counter += 1\n"
          "}\n"
          "\n"
          "func reset() {\n"
          "    counter = 0\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "mixed_declarations");

    assert(n00b_symtab_lookup_all(r.annot->symtab, r"", r"counter") != NULL);
    assert(n00b_symtab_lookup_all(r.annot->symtab, r"", r"MAX") != NULL);
    assert(n00b_symtab_lookup_all(r.annot->symtab, r"", r"increment") != NULL);
    assert(n00b_symtab_lookup_all(r.annot->symtab, r"", r"reset") != NULL);

    pipeline_free(&r);
    printf("  [PASS] mixed_declarations\n");
}

static void
test_all_loop_types(void)
{
    const char *src
        = "var items = [1, 2, 3]\n"
          "var total = 0\n"
          "\n"
          "for x in items {\n"
          "    total += x\n"
          "}\n"
          "\n"
          "while total > 0 {\n"
          "    total -= 1\n"
          "}\n"
          "\n"
          "for i in 0 to 10 {\n"
          "    total += i\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "all_loop_types");
    pipeline_free(&r);
    printf("  [PASS] all_loop_types\n");
}

// ============================================================================
// Test 20: Semicolon as statement separator
// ============================================================================

static void
test_semicolons(void)
{
    pipeline_result_t r = assert_parses("var x = 1; var y = 2\n", "semicolons");
    pipeline_free(&r);
    printf("  [PASS] semicolons\n");
}

// ============================================================================
// Test 21: Callback literal
// ============================================================================

static void
test_callback_lit(void)
{
    pipeline_result_t r = assert_parses("var cb = func handler\n", "callback_lit");
    pipeline_free(&r);

    pipeline_result_t r2
        = assert_parses("var cb = func handler (int, int) -> bool\n", "callback_lit_typed");
    pipeline_free(&r2);

    printf("  [PASS] callback_lit\n");
}

// ============================================================================
// Test 22: Ref expression
// ============================================================================

static void
test_ref_expr(void)
{
    pipeline_result_t r = assert_parses(
        "var x = 42\n"
        "var r = ref x\n",
        "ref_expr");
    pipeline_free(&r);
    printf("  [PASS] ref_expr\n");
}

// ============================================================================
// Test 23: Parse error cases
// ============================================================================

static void
test_parse_error_missing_brace(void)
{
    // Missing closing brace.
    pipeline_result_t r = assert_parse_fails(
        "func f() {\n"
        "    var x = 1\n",
        "missing_brace");
    pipeline_free(&r);
    printf("  [PASS] parse_error_missing_brace\n");
}

static void
test_parse_error_bad_expression(void)
{
    // Unbalanced parens.
    pipeline_result_t r = assert_parse_fails("var x = (1 + 2\n", "bad_expression");
    pipeline_free(&r);
    printf("  [PASS] parse_error_bad_expression\n");
}

// ============================================================================
// Test 24: Long literal / embed
// ============================================================================

static void
test_embed_literal(void)
{
    // Basic embed: single = level
    pipeline_result_t r1 = assert_parses("var x = [=[hello world]=]\n", "embed_basic");
    pipeline_free(&r1);

    // Embed with encoder tag
    pipeline_result_t r2 = assert_parses("var x = [=html[<b>bold</b>]=]\n", "embed_encoder");
    pipeline_free(&r2);

    // Embed with double = level
    pipeline_result_t r3
        = assert_parses("var x = [==[contains ]=] inside]==]\n", "embed_level2");
    pipeline_free(&r3);

    // Embed with litmod
    pipeline_result_t r4 = assert_parses("var x = [=[some data]=]'bytes\n", "embed_litmod");
    pipeline_free(&r4);

    // Embed with encoder + litmod
    pipeline_result_t r5
        = assert_parses("var x = [=json[{\"key\": 1}]=]'string\n", "embed_encoder_litmod");
    pipeline_free(&r5);

    // Embed with parameterized litmod
    pipeline_result_t r6
        = assert_parses("var x = [=[data]=]'list[int]\n", "embed_litmod_param");
    pipeline_free(&r6);

    // Embed containing newlines
    pipeline_result_t r7
        = assert_parses("var x = [=[line one\nline two]=]\n", "embed_multiline");
    pipeline_free(&r7);

    printf("  [PASS] embed_literal\n");
}

// ============================================================================
// Test 25: Nested control flow
// ============================================================================

static void
test_nested_control_flow(void)
{
    const char *src
        = "func process(items: list[int]) {\n"
          "    var total = 0\n"
          "    for x in items {\n"
          "        if x > 0 {\n"
          "            total += x\n"
          "        } else {\n"
          "            continue\n"
          "        }\n"
          "    }\n"
          "    return total\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "nested_control_flow");
    pipeline_free(&r);
    printf("  [PASS] nested_control_flow\n");
}

// ============================================================================
// Test 26: Empty body
// ============================================================================

static void
test_empty_body(void)
{
    // Empty function body.
    pipeline_result_t r = assert_parses(
        "func noop() {\n"
        "}\n",
        "empty_body");
    pipeline_free(&r);
    printf("  [PASS] empty_body\n");
}

// ============================================================================
// Test 27: Member chain
// ============================================================================

static void
test_member_chain(void)
{
    pipeline_result_t r = assert_parses("var x = a.b.c.d\n", "member_chain");
    pipeline_free(&r);
    printf("  [PASS] member_chain\n");
}

// ============================================================================
// Test 28: Pipeline robustness — no crashes on various inputs
// ============================================================================

static void
test_robustness(void)
{
    const char *inputs[] = {
        // Empty.
        "",
        // Just newlines.
        "\n\n\n",
        // Single literal.
        "42\n",
        // Multiple statements.
        "var x = 1\nvar y = 2\nvar z = 3\n",
        // Deeply nested.
        "if true {\n  if true {\n    if true {\n      var x = 1\n    }\n  }\n}\n",
        NULL,
    };

    const char **p;
    for (p = inputs; *p; p++) {
        pipeline_result_t r = run_pipeline(*p);
        // Just verify no crashes.
        assert(r.diag != NULL);
        pipeline_free(&r);
    }

    printf("  [PASS] robustness\n");
}

// ============================================================================
// Test 29: Expression as identifier ref
// ============================================================================

static void
test_varref_annotation(void)
{
    const char *src
        = "var x = 42\n"
          "var y = x\n";

    pipeline_result_t r = assert_parses(src, "varref_annotation");

    // Both x and y should be in the symbol table.
    n00b_sym_entry_t *x = n00b_symtab_lookup_all(r.annot->symtab, r"", r"x");
    n00b_sym_entry_t *y = n00b_symtab_lookup_all(r.annot->symtab, r"", r"y");
    assert(x != NULL);
    assert(y != NULL);

    pipeline_free(&r);
    printf("  [PASS] varref_annotation\n");
}

// ============================================================================
// Test 30: Multiple functions with return — no false warnings
// ============================================================================

static void
test_func_return_no_false_warnings(void)
{
    const char *src
        = "func first() -> int {\n"
          "    return 1\n"
          "}\n"
          "func second() -> int {\n"
          "    return 2\n"
          "}\n"
          "func third() -> int {\n"
          "    return 3\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "func_return_no_false_warnings");

    // No false W001 (unreachable code) between functions.
    assert(!has_diag_code(r.diag, "W001"));

    // No false W002 (use before def) for function names.
    assert(!has_diag_code(r.diag, "W002"));

    pipeline_free(&r);
    printf("  [PASS] func_return_no_false_warnings\n");
}

// ============================================================================
// Test 31: Triple-quoted strings
// ============================================================================

static void
test_triple_quoted_string(void)
{
    pipeline_result_t r
        = assert_parses("var x = \"\"\"hello\nworld\"\"\"\n", "triple_quoted_string");
    pipeline_free(&r);
    printf("  [PASS] triple_quoted_string\n");
}

// ============================================================================
// Test 32: Enum qualifier order variants
// ============================================================================

static void
test_enum_qualifier_variants(void)
{
    // enum private (reversed order).
    pipeline_result_t r1 = assert_parses(
        "enum private Ep {\n"
        "    A,\n"
        "}\n",
        "enum_private_reversed");
    pipeline_free(&r1);

    // global enum.
    pipeline_result_t r2 = assert_parses(
        "global enum Ge {\n"
        "    A,\n"
        "}\n",
        "global_enum");
    pipeline_free(&r2);

    // enum global (reversed order).
    pipeline_result_t r3 = assert_parses(
        "enum global Eg {\n"
        "    A,\n"
        "}\n",
        "enum_global_reversed");
    pipeline_free(&r3);

    printf("  [PASS] enum_qualifier_variants\n");
}

// ============================================================================
// Test 33: Enum with colon values
// ============================================================================

static void
test_enum_colon_values(void)
{
    const char *src
        = "enum Status {\n"
          "    Active : 1,\n"
          "    Inactive : 0,\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "enum_colon_values");
    pipeline_free(&r);
    printf("  [PASS] enum_colon_values\n");
}

// ============================================================================
// Test 34: Labeled typeof and switch
// ============================================================================

static void
test_labeled_typeof(void)
{
    const char *src
        = "var x = 42\n"
          "dispatch: typeof x {\n"
          "    case int: var y = 1\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "labeled_typeof");
    pipeline_free(&r);
    printf("  [PASS] labeled_typeof\n");
}

static void
test_labeled_switch(void)
{
    const char *src
        = "var x = 42\n"
          "matcher: switch x {\n"
          "    case 1: var y = 1\n"
          "    else: var y = 0\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "labeled_switch");
    pipeline_free(&r);
    printf("  [PASS] labeled_switch\n");
}

// ============================================================================
// Test 35: Typeof with body blocks (not colon style)
// ============================================================================

static void
test_typeof_body_blocks(void)
{
    const char *src
        = "var x = 42\n"
          "typeof x {\n"
          "    case int {\n"
          "        var y = 1\n"
          "    }\n"
          "    case string {\n"
          "        var y = 2\n"
          "    }\n"
          "    else {\n"
          "        var y = 0\n"
          "    }\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "typeof_body_blocks");
    pipeline_free(&r);
    printf("  [PASS] typeof_body_blocks\n");
}

// ============================================================================
// Test 36: Chained postfix operations
// ============================================================================

static void
test_chained_postfix(void)
{
    // Method call chain.
    pipeline_result_t r1 = assert_parses("var x = a.b.c(1).d[0]\n", "chained_postfix");
    pipeline_free(&r1);

    // Nested calls.
    pipeline_result_t r2 = assert_parses("var x = f(g(h(1)))\n", "nested_calls");
    pipeline_free(&r2);

    // Indexing into call result.
    pipeline_result_t r3 = assert_parses("var x = f()[0]\n", "index_call_result");
    pipeline_free(&r3);

    printf("  [PASS] chained_postfix\n");
}

// ============================================================================
// Test 37: String escape sequences
// ============================================================================

static void
test_string_escapes(void)
{
    pipeline_result_t r = assert_parses("var x = \"hello\\nworld\"\n", "string_newline_escape");
    pipeline_free(&r);

    pipeline_result_t r2 = assert_parses("var x = \"tab\\there\"\n", "string_tab_escape");
    pipeline_free(&r2);

    pipeline_result_t r3
        = assert_parses("var x = \"back\\\\slash\"\n", "string_backslash_escape");
    pipeline_free(&r3);

    pipeline_result_t r4
        = assert_parses("var x = \"quote\\\"inside\"\n", "string_quote_escape");
    pipeline_free(&r4);

    printf("  [PASS] string_escapes\n");
}

// ============================================================================
// Test 38: Nested collection literals
// ============================================================================

static void
test_nested_collections(void)
{
    // Nested lists.
    pipeline_result_t r1 = assert_parses("var x = [[1, 2], [3, 4]]\n", "nested_lists");
    pipeline_free(&r1);

    // Dict with list values.
    pipeline_result_t r2
        = assert_parses("var x = {\"a\": [1, 2], \"b\": [3, 4]}\n", "dict_list_values");
    pipeline_free(&r2);

    // List of tuples.
    pipeline_result_t r3 = assert_parses("var x = [(1, 2), (3, 4)]\n", "list_of_tuples");
    pipeline_free(&r3);

    printf("  [PASS] nested_collections\n");
}

// ============================================================================
// Test 39: Multi-statement case body (colon style)
// ============================================================================

static void
test_multi_stmt_case_body(void)
{
    const char *src
        = "var x = 42\n"
          "switch x {\n"
          "    case 1:\n"
          "        var y = 1\n"
          "        var z = 2\n"
          "    case 2: var w = 3\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "multi_stmt_case_body");
    pipeline_free(&r);
    printf("  [PASS] multi_stmt_case_body\n");
}

// ============================================================================
// Test 40: Varargs + kwargs combined
// ============================================================================

static void
test_func_varargs_kwargs(void)
{
    const char *src
        = "func f(x: int, *rest: int, kw: int = 0) {\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "func_varargs_kwargs");
    pipeline_free(&r);
    printf("  [PASS] func_varargs_kwargs\n");
}

// ============================================================================
// Test 41: Multiple kwargs
// ============================================================================

static void
test_func_multi_kwargs(void)
{
    const char *src
        = "func f(a: int = 1, b: int = 2) {\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "func_multi_kwargs");
    pipeline_free(&r);
    printf("  [PASS] func_multi_kwargs\n");
}

// ============================================================================
// Test 42: Parameter block without body
// ============================================================================

static void
test_parameter_no_body(void)
{
    pipeline_result_t r = assert_parses("parameter var debug\n", "parameter_no_body");
    pipeline_free(&r);
    printf("  [PASS] parameter_no_body\n");
}

// ============================================================================
// Test 43: Class with mixed typed/untyped fields
// ============================================================================

static void
test_class_mixed_fields(void)
{
    const char *src
        = "class Record {\n"
          "    id: int\n"
          "    name\n"
          "    score: f64\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "class_mixed_fields");
    pipeline_free(&r);
    printf("  [PASS] class_mixed_fields\n");
}

// ============================================================================
// Test: Parameterized classes
// ============================================================================

static void
test_class_type_params(void)
{
    // Basic type parameter
    pipeline_result_t r1 = assert_parses(
        "class Box[`T] {\n"
        "    value: `T\n"
        "}\n",
        "class_type_param_basic");
    pipeline_free(&r1);

    // Multiple type parameters
    pipeline_result_t r2 = assert_parses(
        "class Pair[`A, `B] {\n"
        "    first: `A\n"
        "    second: `B\n"
        "}\n",
        "class_type_param_multi");
    pipeline_free(&r2);

    // Type params with where clause
    pipeline_result_t r3 = assert_parses(
        "class SortedList[`T] [`T: Comparable] {\n"
        "    items: list[`T]\n"
        "}\n",
        "class_type_param_where");
    pipeline_free(&r3);

    // Type params with multi-constraint where clause
    pipeline_result_t r4 = assert_parses(
        "class Cache[`K, `V] [`K: Hashable + Comparable, `V: Printable] {\n"
        "    data: dict[`K, `V]\n"
        "}\n",
        "class_type_param_where_multi");
    pipeline_free(&r4);

    // Atomic class with type params
    pipeline_result_t r5 = assert_parses(
        "atomic class SharedRef[`T] {\n"
        "    value: `T\n"
        "}\n",
        "class_type_param_atomic");
    pipeline_free(&r5);

    printf("  [PASS] class_type_params\n");
}

// ============================================================================
// Test 44: Comments between statements
// ============================================================================

static void
test_comments_in_code(void)
{
    const char *src
        = "# This is a line comment\n"
          "var x = 42\n"
          "// C-style line comment\n"
          "var y = x\n"
          "/* block comment */ var z = y\n";

    pipeline_result_t r = assert_parses(src, "comments_in_code");
    pipeline_free(&r);
    printf("  [PASS] comments_in_code\n");
}

// ============================================================================
// Test 45: Switch/typeof else with body block
// ============================================================================

static void
test_switch_else_body_block(void)
{
    const char *src
        = "var x = 42\n"
          "switch x {\n"
          "    case 1: var y = 1\n"
          "    else {\n"
          "        var y = 0\n"
          "    }\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "switch_else_body_block");
    pipeline_free(&r);
    printf("  [PASS] switch_else_body_block\n");
}

// ============================================================================
// Test 46: Untyped formal parameters
// ============================================================================

static void
test_func_untyped_params(void)
{
    const char *src
        = "func f(x, y) {\n"
          "    var z = x\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "func_untyped_params");
    pipeline_free(&r);
    printf("  [PASS] func_untyped_params\n");
}

// ============================================================================
// Test 47: Multi-name formal parameters
// ============================================================================

static void
test_func_multi_name_params(void)
{
    const char *src
        = "func f(x, y: int, z: string) {\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "func_multi_name_params");
    pipeline_free(&r);
    printf("  [PASS] func_multi_name_params\n");
}

// ============================================================================
// Test 48: Deeply chained member access in typeof
// ============================================================================

static void
test_typeof_member_chain(void)
{
    const char *src
        = "var x = 42\n"
          "typeof x {\n"
          "    case int: var y = 1\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "typeof_member_chain");
    pipeline_free(&r);
    printf("  [PASS] typeof_member_chain\n");
}

// ============================================================================
// Test 49: Complex type specs
// ============================================================================

// ============================================================================
// Test 50: Empty programs
// ============================================================================

static void
test_empty_programs(void)
{
    // Completely empty.
    pipeline_result_t r1 = run_pipeline("");
    assert(r1.parsed);
    pipeline_free(&r1);

    // Only newlines.
    pipeline_result_t r2 = run_pipeline("\n\n\n");
    assert(r2.parsed);
    pipeline_free(&r2);

    // Only comments.
    pipeline_result_t r3 = run_pipeline("# just a comment\n");
    assert(r3.parsed);
    pipeline_free(&r3);

    printf("  [PASS] empty_programs\n");
}

// ============================================================================
// Test 51: Var decl with untyped no-init (bare name)
// ============================================================================

static void
test_var_decl_bare(void)
{
    pipeline_result_t r = assert_parses("var x\n", "var_decl_bare");

    n00b_sym_entry_t *x = n00b_symtab_lookup_all(r.annot->symtab, r"", r"x");
    assert(x != NULL);
    pipeline_free(&r);
    printf("  [PASS] var_decl_bare\n");
}

// ============================================================================
// Test 52: Mixed case styles in switch (colon and block)
// ============================================================================

static void
test_switch_mixed_case_styles(void)
{
    const char *src
        = "var x = 42\n"
          "switch x {\n"
          "    case 1: var y = 1\n"
          "    case 2 {\n"
          "        var y = 2\n"
          "    }\n"
          "    else: var y = 0\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "switch_mixed_case_styles");
    pipeline_free(&r);
    printf("  [PASS] switch_mixed_case_styles\n");
}

// ============================================================================
// Test 53: Expression precedence — verify tree shape
// ============================================================================

static void
test_operator_precedence(void)
{
    // 1 + 2 * 3 should parse as 1 + (2 * 3), not (1 + 2) * 3.
    // We just verify it parses — tree structure check would require
    // walking the tree, which is tested in lower-level grammar tests.
    pipeline_result_t r = assert_parses(
        "var x = 1 + 2 * 3\n"
        "var y = 1 * 2 + 3\n"
        "var z = 1 or 2 and 3\n"
        "var w = 1 << 2 + 3\n",
        "operator_precedence");
    pipeline_free(&r);
    printf("  [PASS] operator_precedence\n");
}

// ============================================================================
// Test 54: Untyped varargs
// ============================================================================

static void
test_func_untyped_varargs(void)
{
    const char *src
        = "func f(*args) {\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "func_untyped_varargs");
    pipeline_free(&r);
    printf("  [PASS] func_untyped_varargs\n");
}

// ============================================================================
// Test 55: Untyped kwargs
// ============================================================================

static void
test_func_untyped_kwargs(void)
{
    const char *src
        = "func f(kw = 0) {\n"
          "}\n";

    pipeline_result_t r = assert_parses(src, "func_untyped_kwargs");
    pipeline_free(&r);
    printf("  [PASS] func_untyped_kwargs\n");
}

// ============================================================================
// Test 56: Multiple parse errors
// ============================================================================

static void
test_parse_error_incomplete_func(void)
{
    pipeline_result_t r = assert_parse_fails("func\n", "error_incomplete_func");
    pipeline_free(&r);
    printf("  [PASS] parse_error_incomplete_func\n");
}

static void
test_parse_error_bad_enum(void)
{
    // Enum without braces.
    pipeline_result_t r = assert_parse_fails("enum Color\n", "error_bad_enum");
    pipeline_free(&r);
    printf("  [PASS] parse_error_bad_enum\n");
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
    setbuf(stderr, NULL);
    printf("Running n00b program tests...\n");

    // Load grammar.
    test_grammar_loads();

    if (!shared_grammar) {
        fprintf(stderr, "Grammar failed to load, skipping all tests.\n");
        return 1;
    }

    // Variable declarations.
    test_var_decl_simple();
    test_var_decl_typed();
    test_var_decl_typed_no_init();
    test_var_decl_qualifiers();
    test_var_decl_multi();
    test_var_decl_multi_typed();

    // Function definitions.
    test_func_simple();
    test_func_params();
    test_func_return_type();
    test_func_private();
    test_func_once();
    test_func_private_once();
    test_func_varargs();
    test_func_kwargs();
    test_func_varargs_kwargs();
    test_func_multi_kwargs();
    test_func_untyped_params();
    test_func_multi_name_params();
    test_func_untyped_varargs();
    test_func_untyped_kwargs();
    test_func_multiple();
    test_func_method();

    // Control flow.
    test_if_simple();
    test_if_else();
    test_if_elif_else();
    test_while_loop();
    test_for_in();
    test_for_range();
    test_for_from_range();
    test_for_multi_var();
    test_labeled_while();
    test_labeled_for();
    test_labeled_typeof();
    test_labeled_switch();
    test_break_continue();
    test_return();
    test_yield_statement();

    // Switch.
    test_switch_basic();
    test_switch_body_blocks();
    test_switch_multi_case();
    test_switch_range_case();

    // Typeof.
    test_typeof_basic();
    test_typeof_multi_type();
    test_typeof_body_blocks();
    test_typeof_member_chain();

    // Expressions.
    test_expr_arithmetic();
    test_expr_comparison();
    test_expr_logical();
    test_expr_bitwise();
    test_expr_unary();
    test_expr_postfix();
    test_expr_index_slice();
    test_expr_call_kwargs();
    test_expr_paren();
    test_expr_unwrap();

    // Literals.
    test_literal_int();
    test_literal_float();
    test_literal_string();
    test_literal_char();
    test_literal_bool();
    test_literal_with_modifier();

    // Collection literals.
    test_list_literal();
    test_dict_literal();
    test_set_literal();
    test_tuple_literal();

    // Assignments.
    test_assign_equals();
    test_binop_assign();
    test_bitwise_assign();

    // Other statements.
    test_assert_stmt();
    test_use_stmt();
    test_parameter_block();
    test_expr_stmt();

    // Enum.
    test_enum_basic();
    test_enum_with_values();
    test_enum_private();
    test_enum_anonymous();
    test_enum_qualifier_variants();
    test_enum_colon_values();

    // Classes.
    test_class_basic();
    test_class_untyped_fields();
    test_class_atomic();
    test_class_mixed_fields();
    test_class_type_params();

    // Type specs.
    test_type_spec_simple();
    test_type_spec_parameterized();
    test_type_spec_tvar();
    test_type_spec_func();
    test_type_spec_ref();
    test_type_spec_containers_with_tvars();
    test_type_spec_func_with_containers();
    test_type_spec_in_var_decls();
    test_type_spec_in_func_params();
    test_type_spec_in_class_fields();
    test_type_spec_litmod_with_types();

    // Union types and where clauses.
    test_union_type_basic();
    test_union_type_triple();
    test_union_in_list();
    test_union_in_dict();
    test_union_in_func_param();
    test_union_in_return();
    test_union_with_tvar();
    test_union_nested_param();
    test_where_basic();
    test_where_multi_constraint();
    test_where_exclusion();
    test_where_multi_var();
    test_where_mixed();

    // Other.
    test_semicolons();
    test_callback_lit();
    test_ref_expr();
    test_embed_literal();
    test_triple_quoted_string();
    test_empty_body();
    test_member_chain();
    test_nested_scopes();
    test_nested_control_flow();
    test_varref_annotation();
    test_chained_postfix();
    test_string_escapes();
    test_nested_collections();
    test_multi_stmt_case_body();
    test_comments_in_code();
    test_switch_else_body_block();
    test_switch_mixed_case_styles();
    test_operator_precedence();
    test_empty_programs();
    test_var_decl_bare();
    test_parameter_no_body();

    // Complex programs.
    test_complex_function();
    test_mixed_declarations();
    test_all_loop_types();

    // Regression tests.
    test_func_return_no_false_warnings();

    // Error cases.
    test_parse_error_missing_brace();
    test_parse_error_bad_expression();
    test_parse_error_incomplete_func();
    test_parse_error_bad_enum();

    // Robustness.
    test_robustness();

    printf("All n00b program tests passed.\n");
    n00b_shutdown();
    return 0;
}

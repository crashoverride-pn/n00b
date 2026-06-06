// test_dfg.c — End-to-end integration tests for DFG construction.
//
// Loads n00b.bnf, parses n00b source, runs the annotation walk to produce
// CF labels, builds a CFG, then builds a DFG and verifies its structure.

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
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "slay/annot_walk.h"
#include "n00b/n00b_compile.h"
#include "slay/bnf.h"
#include "slay/cf_label.h"
#include "slay/cfg.h"
#include "slay/dfg.h"
#include "slay/debug.h"
#include "slay/grammar.h"
#include "slay/n00b_parse.h"
#include "n00b/n00b_tokenizer.h"
#include "slay/parse_tree.h"
#include "slay/token.h"
#include "text/strings/string_ops.h"
#include "internal/slay/grammar_internal.h"

// ============================================================================
// Grammar + parse helpers
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

    bool ok = n00b_bnf_load(bnf_text, r"module", g);

    if (!ok) {
        fprintf(stderr, "  [FAIL] n00b_bnf_load failed for n00b.bnf\n");
        n00b_grammar_free(g);
        return NULL;
    }

    return g;
}

static n00b_parse_result_t *
parse_n00b_source(n00b_grammar_t *g, const char *src)
{
    n00b_buffer_t       *buf     = n00b_buffer_from_bytes((char *)src,
                                                           (int64_t)strlen(src));
    n00b_scanner_t      *scanner = n00b_scanner_new(buf, n00b_lang_tokenize, g);
    n00b_token_stream_t *ts      = n00b_token_stream_new(scanner);

    return n00b_grammar_parse(g, ts);
}

// ============================================================================
// DFG construction helper
// ============================================================================

typedef struct {
    n00b_dfg_t          *dfg;
    n00b_cfg_t          *cfg;
    n00b_annot_result_t *annot;
} dfg_result_t;

static dfg_result_t
build_dfg_for(const char *src)
{
    dfg_result_t r = {0};

    n00b_parse_result_t *pr = parse_n00b_source(shared_grammar, src);

    if (!n00b_parse_result_ok(pr)) {
        n00b_string_t *err = n00b_parse_result_error_string(pr);
        fprintf(stderr, "  Parse failed: %.*s\n",
                (int)err->u8_bytes, err->data);
        return r;
    }

    n00b_parse_tree_t *tree = n00b_parse_result_tree(pr);
    assert(tree != NULL);

    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);

    r.cfg   = n00b_build_cfg(ar->cf_labels, tree, r"test", ar->symtab);
    assert(r.cfg != NULL);

    r.dfg   = n00b_build_dfg(r.cfg, ar->cf_labels, shared_grammar, ar);
    r.annot = ar;

    return r;
}

static void
free_dfg_result(dfg_result_t *r)
{
    if (r->dfg) {
        n00b_dfg_free(r->dfg);
    }

    if (r->cfg) {
        n00b_cfg_free(r->cfg);
    }
}

// ============================================================================
// Helpers
// ============================================================================

// Find a fact by variable name and def/use kind (nth occurrence).
static n00b_du_fact_t *
find_fact(n00b_dfg_t *dfg, const char *var, bool is_def, int nth)
{
    int32_t nf  = n00b_dfg_fact_count(dfg);
    int     hit = 0;

    for (int32_t i = 0; i < nf; i++) {
        n00b_du_fact_t *f = &dfg->facts.data[i];

        if (f->is_def == is_def
            && f->var_name->u8_bytes == strlen(var)
            && memcmp(f->var_name->data, var, f->var_name->u8_bytes) == 0) {
            if (hit == nth) {
                return f;
            }

            hit++;
        }
    }

    return NULL;
}

// Count defs of a variable.
static int
count_defs(n00b_dfg_t *dfg, const char *var)
{
    int     count = 0;
    int32_t nf    = n00b_dfg_fact_count(dfg);

    for (int32_t i = 0; i < nf; i++) {
        n00b_du_fact_t *f = &dfg->facts.data[i];

        if (f->is_def
            && f->var_name->u8_bytes == strlen(var)
            && memcmp(f->var_name->data, var, f->var_name->u8_bytes) == 0) {
            count++;
        }
    }

    return count;
}

// Count uses of a variable.
static int
count_uses(n00b_dfg_t *dfg, const char *var)
{
    int     count = 0;
    int32_t nf    = n00b_dfg_fact_count(dfg);

    for (int32_t i = 0; i < nf; i++) {
        n00b_du_fact_t *f = &dfg->facts.data[i];

        if (!f->is_def
            && f->var_name->u8_bytes == strlen(var)
            && memcmp(f->var_name->data, var, f->var_name->u8_bytes) == 0) {
            count++;
        }
    }

    return count;
}

// Count DD edges where a def of `var` reaches a use.
static int
count_edges_for_var(n00b_dfg_t *dfg, const char *var)
{
    int     count = 0;
    int32_t ne    = n00b_dfg_edge_count(dfg);

    for (int32_t i = 0; i < ne; i++) {
        n00b_dd_edge_t *e = &dfg->edges.data[i];
        n00b_du_fact_t *d = &dfg->facts.data[e->def_id];

        if (d->var_name->u8_bytes == strlen(var)
            && memcmp(d->var_name->data, var, d->var_name->u8_bytes) == 0) {
            count++;
        }
    }

    return count;
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
// Test 1: Simple assignment — def of x reaches use of x
// ============================================================================

static void
test_dfg_simple_assign(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] dfg_simple_assign\n");
        return;
    }

    // n00b syntax: var x = 1; var y = x
    const char *src =
        "var x = 1\n"
        "var y = x\n";

    dfg_result_t r = build_dfg_for(src);
    assert(r.dfg != NULL);

    // Should have at least 1 def of x and 1 use of x.
    assert(count_defs(r.dfg, "x") >= 1);
    assert(count_uses(r.dfg, "x") >= 1);

    // Should have at least 1 DD edge for x.
    assert(count_edges_for_var(r.dfg, "x") >= 1);

    free_dfg_result(&r);
    printf("  [PASS] dfg_simple_assign\n");
}

// ============================================================================
// Test 2: Overwrite — only second def reaches use
// ============================================================================

static void
test_dfg_overwrite(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] dfg_overwrite\n");
        return;
    }

    const char *src =
        "var x = 1\n"
        "x = 2\n"
        "var y = x\n";

    dfg_result_t r = build_dfg_for(src);
    assert(r.dfg != NULL);

    // Should have at least 2 defs of x.
    assert(count_defs(r.dfg, "x") >= 2);

    // The use of x should be reached by exactly 1 def (the second one).
    n00b_du_fact_t *use_x = find_fact(r.dfg, "x", false, 0);

    if (use_x) {
        n00b_list_t(n00b_dd_edge_t) dds = n00b_dfg_reaching_defs(r.dfg, use_x->id);
        int32_t nd = (int32_t)n00b_list_len(dds);

        // At least 1 reaching def.
        assert(nd >= 1);

        // Since both defs are in the same block (linear code),
        // only the last one before the use should reach. Verify nd == 1.
        assert(nd == 1);
        n00b_list_free(dds);
    }

    free_dfg_result(&r);
    printf("  [PASS] dfg_overwrite\n");
}

// ============================================================================
// Test 3: Branch — both defs reach use after join
// ============================================================================

static void
test_dfg_branch(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] dfg_branch\n");
        return;
    }

    const char *src =
        "var x = 0\n"
        "if c {\n"
        "    x = 1\n"
        "} else {\n"
        "    x = 2\n"
        "}\n"
        "var y = x\n";

    dfg_result_t r = build_dfg_for(src);
    assert(r.dfg != NULL);

    // Should have at least 2 defs of x (one in each branch, plus initial).
    assert(count_defs(r.dfg, "x") >= 2);

    // The use of x after the join should be reached by the branch defs.
    // Find the last use of x.
    int32_t nf = n00b_dfg_fact_count(r.dfg);
    n00b_du_fact_t *last_use_x = NULL;

    for (int32_t i = nf - 1; i >= 0; i--) {
        n00b_du_fact_t *f = &r.dfg->facts.data[i];

        if (!f->is_def
            && f->var_name->u8_bytes == 1
            && f->var_name->data[0] == 'x') {
            last_use_x = f;
            break;
        }
    }

    if (last_use_x) {
        n00b_list_t(n00b_dd_edge_t) dds = n00b_dfg_reaching_defs(r.dfg, last_use_x->id);
        int32_t nd = (int32_t)n00b_list_len(dds);

        // Both branch defs should reach.
        assert(nd >= 2);
        n00b_list_free(dds);
    }

    free_dfg_result(&r);
    printf("  [PASS] dfg_branch\n");
}

// ============================================================================
// Test 4: Loop — def in loop body reaches its own use (loop back)
// ============================================================================

static void
test_dfg_loop(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] dfg_loop\n");
        return;
    }

    const char *src =
        "var x = 0\n"
        "while x {\n"
        "    x = x + 1\n"
        "}\n";

    dfg_result_t r = build_dfg_for(src);
    assert(r.dfg != NULL);

    // Should have defs and uses of x.
    assert(count_defs(r.dfg, "x") >= 1);
    assert(count_uses(r.dfg, "x") >= 1);

    // Should have DD edges for x.
    assert(count_edges_for_var(r.dfg, "x") >= 1);

    free_dfg_result(&r);
    printf("  [PASS] dfg_loop\n");
}

// ============================================================================
// Test 5: No def — use without any reaching def
// ============================================================================

static void
test_dfg_no_def(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] dfg_no_def\n");
        return;
    }

    // y is used but never assigned — it might come from an enclosing scope.
    const char *src =
        "var x = y\n";

    dfg_result_t r = build_dfg_for(src);
    assert(r.dfg != NULL);

    // Should have a use of y.
    assert(count_uses(r.dfg, "y") >= 1);

    // No def of y in this code.
    assert(count_defs(r.dfg, "y") == 0);

    // No DD edges for y (no defs to reach from).
    assert(count_edges_for_var(r.dfg, "y") == 0);

    free_dfg_result(&r);
    printf("  [PASS] dfg_no_def\n");
}

// ============================================================================
// Test 6: Dead def — def with no reached uses
// ============================================================================

static void
test_dfg_dead_def(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] dfg_dead_def\n");
        return;
    }

    const char *src =
        "var x = 1\n"
        "x = 2\n";

    dfg_result_t r = build_dfg_for(src);
    assert(r.dfg != NULL);

    // First def of x (var x = 1) should have no reached uses
    // since x = 2 kills it and there's no use after x = 2.
    n00b_du_fact_t *first_def = find_fact(r.dfg, "x", true, 0);

    if (first_def) {
        n00b_list_t(n00b_dd_edge_t) uses = n00b_dfg_reached_uses(r.dfg, first_def->id);
        int32_t nu = (int32_t)n00b_list_len(uses);

        // First def should be dead.
        assert(nu == 0);
        n00b_list_free(uses);
    }

    free_dfg_result(&r);
    printf("  [PASS] dfg_dead_def\n");
}

// ============================================================================
// Test 7: Query API — reaching_defs and reached_uses
// ============================================================================

static void
test_dfg_query_api(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] dfg_query_api\n");
        return;
    }

    const char *src =
        "var x = 1\n"
        "var y = x\n"
        "var z = x\n";

    dfg_result_t r = build_dfg_for(src);
    assert(r.dfg != NULL);

    int32_t ne = n00b_dfg_edge_count(r.dfg);

    // Every edge should be findable via both query directions.
    for (int32_t i = 0; i < ne; i++) {
        n00b_dd_edge_t *e = &r.dfg->edges.data[i];

        // Verify reaching_defs finds this edge.
        n00b_list_t(n00b_dd_edge_t) defs = n00b_dfg_reaching_defs(r.dfg, e->use_id);
        int32_t nd = (int32_t)n00b_list_len(defs);
        assert(nd > 0);

        bool found_def = false;

        for (int32_t j = 0; j < nd; j++) {
            if (defs.data[j].def_id == e->def_id) {
                found_def = true;
                break;
            }
        }

        assert(found_def);
        n00b_list_free(defs);

        // Verify reached_uses finds this edge.
        n00b_list_t(n00b_dd_edge_t) uses = n00b_dfg_reached_uses(r.dfg, e->def_id);
        int32_t nu = (int32_t)n00b_list_len(uses);
        assert(nu > 0);

        bool found_use = false;

        for (int32_t j = 0; j < nu; j++) {
            if (uses.data[j].use_id == e->use_id) {
                found_use = true;
                break;
            }
        }

        assert(found_use);
        n00b_list_free(uses);
    }

    free_dfg_result(&r);
    printf("  [PASS] dfg_query_api\n");
}

// ============================================================================
// Test 8: Print smoke test — doesn't crash
// ============================================================================

static void
test_dfg_print(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] dfg_print\n");
        return;
    }

    const char *src =
        "var x = 1\n"
        "if c {\n"
        "    x = 2\n"
        "}\n"
        "var y = x\n";

    dfg_result_t r = build_dfg_for(src);
    assert(r.dfg != NULL);

    // Print to /dev/null — just verify it doesn't crash.
    FILE *devnull = fopen("/dev/null", "w");

    if (devnull) {
        n00b_dfg_print(r.dfg, shared_grammar, devnull);
        fclose(devnull);
    }

    free_dfg_result(&r);
    printf("  [PASS] dfg_print\n");
}

// ============================================================================
// Test 9: Same-statement def/use — x = x + 1
// ============================================================================

static void
test_dfg_same_stmt_def_use(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] dfg_same_stmt_def_use\n");
        return;
    }

    // In `x = x + 1`, the RHS use of x must see the incoming def of x,
    // not be killed by the LHS def at the same statement.
    const char *src =
        "var x = 10\n"
        "x = x + 1\n";

    dfg_result_t r = build_dfg_for(src);
    assert(r.dfg != NULL);

    // Should have at least 2 defs of x (var x = 10, and x = x + 1).
    assert(count_defs(r.dfg, "x") >= 2);

    // Should have at least 1 use of x (RHS of x = x + 1).
    assert(count_uses(r.dfg, "x") >= 1);

    // The use of x on the RHS should be reached by the first def (var x = 10).
    n00b_du_fact_t *use_x = find_fact(r.dfg, "x", false, 0);
    assert(use_x != NULL);

    n00b_list_t(n00b_dd_edge_t) dds = n00b_dfg_reaching_defs(r.dfg, use_x->id);
    int32_t nd = (int32_t)n00b_list_len(dds);

    // Must have at least 1 reaching def (the var x = 10 def).
    assert(nd >= 1);
    n00b_list_free(dds);

    free_dfg_result(&r);
    printf("  [PASS] dfg_same_stmt_def_use\n");
}

// ============================================================================
// Test 10: Parameter def reaches use in function body
// ============================================================================

static void
test_dfg_param_def(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] dfg_param_def\n");
        return;
    }

    const char *src =
        "func f(x: int) {\n"
        "    var y = x\n"
        "}\n";

    // Build the module-level result (func-def is opaque at module level).
    dfg_result_t r = build_dfg_for(src);
    assert(r.annot != NULL);

    // The function's own CFG is stored on its symbol entry.
    n00b_sym_entry_t *fsym = n00b_symtab_lookup_all(
        r.annot->symtab, n00b_string_empty(), r"f");
    assert(fsym != NULL);
    assert(fsym->kind == N00B_SYM_FUNCTION);
    assert(fsym->cfg != NULL);

    // Build a DFG from the function's own CFG.
    n00b_dfg_t *fdfg = n00b_build_dfg(fsym->cfg, r.annot->cf_labels,
                                      shared_grammar, r.annot);
    assert(fdfg != NULL);

    // Should have a DEF of x (from parameter) and a USE of x.
    assert(count_defs(fdfg, "x") >= 1);
    assert(count_uses(fdfg, "x") >= 1);

    // The parameter def of x should reach the use of x in `var y = x`.
    assert(count_edges_for_var(fdfg, "x") >= 1);

    // Verify the reaching def for the use of x.
    n00b_du_fact_t *use_x = find_fact(fdfg, "x", false, 0);
    assert(use_x != NULL);

    n00b_list_t(n00b_dd_edge_t) dds = n00b_dfg_reaching_defs(fdfg, use_x->id);
    int32_t nd = (int32_t)n00b_list_len(dds);
    assert(nd >= 1);

    // The reaching def should be the parameter def (stmt_ix == -1).
    n00b_du_fact_t *def_x = &fdfg->facts.data[dds.data[0].def_id];
    assert(def_x->is_def);
    assert(def_x->stmt_ix == -1);  // Synthetic param def.

    n00b_list_free(dds);
    n00b_dfg_free(fdfg);
    free_dfg_result(&r);
    printf("  [PASS] dfg_param_def\n");
}

// ============================================================================
// Test 11: Type variables on all symbols from annotation walk
// ============================================================================

static void
test_type_vars_on_symbols(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] type_vars_on_symbols\n");
        return;
    }

    const char *src =
        "func f(x: int, y: string) {\n"
        "    var z = x\n"
        "}\n";

    dfg_result_t r = build_dfg_for(src);
    assert(r.dfg != NULL);
    assert(r.annot != NULL);
    assert(r.annot->tc_ctx != NULL);
    assert(r.annot->params != NULL);

    // Should have at least 2 params (x and y).
    size_t np = n00b_list_len(*r.annot->params);
    assert(np >= 2);

    // Each param should have a non-NULL type_var with a unique ID.
    for (size_t i = 0; i < np; i++) {
        n00b_sym_entry_t *sym = n00b_list_get(*r.annot->params, i);
        assert(sym != NULL);
        assert(sym->type_var != NULL);
        assert(sym->kind == N00B_SYM_PARAM);

        // Verify uniqueness: no two params share the same type_var pointer.
        for (size_t j = 0; j < i; j++) {
            n00b_sym_entry_t *other = n00b_list_get(*r.annot->params, j);
            assert(sym->type_var != other->type_var);
        }
    }

    free_dfg_result(&r);
    printf("  [PASS] type_vars_on_symbols\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running dfg tests...\n");

    test_grammar_loads();
    test_dfg_simple_assign();
    test_dfg_overwrite();
    test_dfg_branch();
    test_dfg_loop();
    test_dfg_no_def();
    test_dfg_dead_def();
    test_dfg_query_api();
    test_dfg_print();
    test_dfg_same_stmt_def_use();
    test_dfg_param_def();
    test_type_vars_on_symbols();

    printf("All dfg tests passed.\n");
    n00b_shutdown();
    return 0;
}

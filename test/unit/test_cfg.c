// test_cfg.c — End-to-end integration tests for CFG construction.
//
// Loads c_ncc.bnf, parses C source, runs the annotation walk to produce
// CF labels, then builds a CFG and verifies its structure.

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
#include "parsers/scan_recipes.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "slay/annot_walk.h"
#include "slay/bnf.h"
#include "slay/cf_label.h"
#include "slay/cfg.h"
#include "slay/grammar.h"
#include "slay/n00b_parse.h"
#include "slay/parse_tree.h"
#include "slay/token.h"
#include "text/strings/string_ops.h"
#include "internal/slay/grammar_internal.h"
#include "n00b/n00b_compile.h"

// ============================================================================
// C tokenizer (duplicated from test_c_parse.c)
// ============================================================================

static bool
c_ident_start(uint8_t b)
{
    return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_';
}

static bool
c_ident_continue(uint8_t b)
{
    return c_ident_start(b) || (b >= '0' && b <= '9');
}

static n00b_option_t(n00b_string_t *)
c_scan_identifier(n00b_scanner_t *s)
{
    if (n00b_scan_at_eof(s) || !c_ident_start(n00b_scan_peek_byte(s, 0))) {
        return n00b_option_none(n00b_string_t *);
    }

    n00b_scan_mark(s);
    n00b_scan_advance(s);

    while (!n00b_scan_at_eof(s) && c_ident_continue(n00b_scan_peek_byte(s, 0))) {
        n00b_scan_advance(s);
    }

    return n00b_option_set(n00b_string_t *, n00b_scan_extract(s));
}

static bool
c_tokenize(n00b_scanner_t *s)
{
restart:
    n00b_scan_skip_whitespace(s);

    if (n00b_scan_at_eof(s)) {
        return false;
    }

    if (n00b_scan_peek_byte(s, 0) == '/'
        && n00b_scan_peek_byte(s, 1) == '/') {
        n00b_scan_skip_line_comment(s);
        goto restart;
    }

    if (n00b_scan_peek_byte(s, 0) == '/'
        && n00b_scan_peek_byte(s, 1) == '*') {
        n00b_scan_skip_block_comment(s, "/*", "*/");
        goto restart;
    }

    n00b_scan_mark(s);
    n00b_codepoint_t cp = n00b_scan_peek(s, 0);

    if (cp == '"') {
        n00b_option_t(n00b_string_t *) val = n00b_scan_string_double(s);
        n00b_scan_emit(s, .token_type = "STRING_LIT", .contents = val);
        return true;
    }

    if (cp == '\'') {
        n00b_option_t(n00b_string_t *) val = n00b_scan_string_single(s);
        n00b_scan_emit(s, .token_type = "CHAR_LIT", .contents = val);
        return true;
    }

    if ((cp >= '0' && cp <= '9')
        || (cp == '.' && n00b_scan_peek_byte(s, 1) >= '0'
            && n00b_scan_peek_byte(s, 1) <= '9')) {
        bool emitted = n00b_scan_number(s, "INTEGER", "FLOAT");

        if (emitted) {
            return true;
        }
    }

    if ((cp >= 'a' && cp <= 'z') || (cp >= 'A' && cp <= 'Z') || cp == '_') {
        n00b_option_t(n00b_string_t *) id_val = c_scan_identifier(s);

        if (n00b_option_is_set(id_val)) {
            n00b_token_err_t err = n00b_scan_emit(s, .contents = id_val);

            if (err == N00B_TOK_ERR_NOT_IN_GRAMMAR) {
                n00b_scan_emit(s, .token_type = "IDENTIFIER",
                               .contents = id_val);
            }

            return true;
        }
    }

    // 3-char operators.
    static const char *ops3[] = {
        "<<=", ">>=", "...", NULL,
    };

    const char **op;
    for (op = ops3; *op; op++) {
        if (n00b_scan_peek_byte(s, 0) == (uint8_t)(*op)[0]
            && n00b_scan_peek_byte(s, 1) == (uint8_t)(*op)[1]
            && n00b_scan_peek_byte(s, 2) == (uint8_t)(*op)[2]) {
            size_t   save_cur = s->cursor;
            uint32_t save_ln  = s->line;
            uint32_t save_col = s->column;

            n00b_scan_advance_n(s, 3);
            n00b_token_err_t err = n00b_scan_emit(s);

            if (err == N00B_TOK_OK) {
                return true;
            }

            s->cursor = save_cur;
            s->line   = save_ln;
            s->column = save_col;
        }
    }

    // 2-char operators.
    static const char *ops2[] = {
        "->", "++", "--", "<<", ">>", "<=", ">=", "==", "!=",
        "&&", "||", "+=", "-=", "*=", "/=", "%=", "&=", "^=",
        "|=", "::", NULL,
    };

    for (op = ops2; *op; op++) {
        if (n00b_scan_peek_byte(s, 0) == (uint8_t)(*op)[0]
            && n00b_scan_peek_byte(s, 1) == (uint8_t)(*op)[1]) {
            size_t   save_cur = s->cursor;
            uint32_t save_ln  = s->line;
            uint32_t save_col = s->column;

            n00b_scan_advance_n(s, 2);
            n00b_token_err_t err = n00b_scan_emit(s);

            if (err == N00B_TOK_OK) {
                return true;
            }

            s->cursor = save_cur;
            s->line   = save_ln;
            s->column = save_col;
        }
    }

    n00b_scan_advance(s);

    n00b_token_err_t err = n00b_scan_emit(s);

    if (err != N00B_TOK_OK) {
        n00b_scan_emit(s, .token_type = "OTHER");
    }

    return true;
}

// ============================================================================
// Grammar + parse helpers
// ============================================================================

static n00b_grammar_t *shared_grammar = NULL;

static n00b_grammar_t *
load_c_grammar(void)
{
    const char *paths[] = {
        "grammars/c_ncc.bnf",
        "../grammars/c_ncc.bnf",
        "../../grammars/c_ncc.bnf",
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
        (void)asprintf(&path, "%s/grammars/c_ncc.bnf", srcroot);
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

    bool ok = n00b_bnf_load(bnf_text, r"translation_unit", g);

    if (!ok) {
        fprintf(stderr, "  [FAIL] n00b_bnf_load failed for c_ncc.bnf\n");
        n00b_grammar_free(g);
        return NULL;
    }

    return g;
}

static n00b_parse_result_t *
parse_c_source(n00b_grammar_t *g, const char *src)
{
    n00b_buffer_t       *buf     = n00b_buffer_from_bytes((char *)src,
                                                           (int64_t)strlen(src));
    n00b_scanner_t      *scanner = n00b_scanner_new(buf, c_tokenize, g);
    n00b_token_stream_t *ts      = n00b_token_stream_new(scanner);

    return n00b_grammar_parse(g, ts);
}

// ============================================================================
// CFG construction helper
// ============================================================================

typedef struct {
    n00b_cfg_t          *cfg;
    n00b_annot_result_t *annot;
} cfg_result_t;

static cfg_result_t
build_cfg_for(const char *src)
{
    cfg_result_t r = {0};

    n00b_parse_result_t *pr = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(pr));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(pr);
    assert(tree != NULL);

    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);

    r.cfg   = n00b_build_cfg(ar->cf_labels, tree, r"test", ar->symtab);
    r.annot = ar;

    return r;
}

// ============================================================================
// Edge counting helpers
// ============================================================================

static int32_t
count_edges_of_kind(n00b_cfg_t *cfg, n00b_cfg_edge_kind_t kind)
{
    int32_t count = 0;
    size_t  ne    = n00b_list_len(cfg->edges);

    for (size_t i = 0; i < ne; i++) {
        if (cfg->edges.data[i].kind == kind) {
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
    shared_grammar = load_c_grammar();
    assert(shared_grammar != NULL);
    n00b_gc_register_root(shared_grammar);
    printf("  [PASS] grammar_loads\n");
}

// ============================================================================
// Test 1: Linear code — no branching
// ============================================================================

static void
test_cfg_linear(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] cfg_linear\n");
        return;
    }

    const char *src = "void f(void) { int x; int y; int z; }\n";

    cfg_result_t r = build_cfg_for(src);
    assert(r.cfg != NULL);

    // Should have entry + exit + possibly more blocks, but no branch edges.
    assert(n00b_cfg_block_count(r.cfg) >= 2);
    assert(count_edges_of_kind(r.cfg, N00B_CFG_BRANCH_TRUE) == 0);
    assert(count_edges_of_kind(r.cfg, N00B_CFG_BRANCH_FALSE) == 0);

    // Entry block should be marked.
    n00b_cfg_block_t *entry = n00b_cfg_entry(r.cfg);
    assert(entry != NULL);
    assert(entry->is_entry);

    // Exit block should be marked.
    n00b_cfg_block_t *exit_blk = n00b_cfg_exit(r.cfg);
    assert(exit_blk != NULL);
    assert(exit_blk->is_exit);

    n00b_cfg_free(r.cfg);
    printf("  [PASS] cfg_linear\n");
}

// ============================================================================
// Test 2: If-else creates branch edges
// ============================================================================

static void
test_cfg_if_else(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] cfg_if_else\n");
        return;
    }

    const char *src =
        "void f(int x) {\n"
        "    if (x) { int y; } else { int z; }\n"
        "}\n";

    cfg_result_t r = build_cfg_for(src);
    assert(r.cfg != NULL);

    // Must have true and false branch edges.
    assert(count_edges_of_kind(r.cfg, N00B_CFG_BRANCH_TRUE) >= 1);
    assert(count_edges_of_kind(r.cfg, N00B_CFG_BRANCH_FALSE) >= 1);

    n00b_cfg_free(r.cfg);
    printf("  [PASS] cfg_if_else\n");
}

// ============================================================================
// Test 3: While loop creates loop edges
// ============================================================================

static void
test_cfg_while(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] cfg_while\n");
        return;
    }

    const char *src =
        "void f(void) {\n"
        "    while (x) { y(); }\n"
        "}\n";

    cfg_result_t r = build_cfg_for(src);
    assert(r.cfg != NULL);

    assert(count_edges_of_kind(r.cfg, N00B_CFG_LOOP_BACK) >= 1);
    assert(count_edges_of_kind(r.cfg, N00B_CFG_LOOP_EXIT) >= 1);

    n00b_cfg_free(r.cfg);
    printf("  [PASS] cfg_while\n");
}

// ============================================================================
// Test 4: Break/continue create jump edges
// ============================================================================

static void
test_cfg_break_continue(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] cfg_break_continue\n");
        return;
    }

    const char *src =
        "void f(void) {\n"
        "    while (1) {\n"
        "        if (x) break;\n"
        "        continue;\n"
        "    }\n"
        "}\n";

    cfg_result_t r = build_cfg_for(src);
    assert(r.cfg != NULL);

    // break + continue produce jump edges.
    assert(count_edges_of_kind(r.cfg, N00B_CFG_JUMP) >= 2);

    n00b_cfg_free(r.cfg);
    printf("  [PASS] cfg_break_continue\n");
}

// ============================================================================
// Test 5: Return creates jump edge to exit
// ============================================================================

static void
test_cfg_return(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] cfg_return\n");
        return;
    }

    const char *src = "int f(int x) { if (x) return 1; return 0; }\n";

    cfg_result_t r = build_cfg_for(src);
    assert(r.cfg != NULL);

    // Two return statements => two jump edges targeting exit.
    int32_t jumps = count_edges_of_kind(r.cfg, N00B_CFG_JUMP);
    assert(jumps >= 2);

    // Verify jump edges target the exit block.
    size_t ne = n00b_list_len(r.cfg->edges);
    int32_t jumps_to_exit = 0;

    for (size_t i = 0; i < ne; i++) {
        n00b_cfg_edge_t *e = &r.cfg->edges.data[i];

        if (e->kind == N00B_CFG_JUMP && e->to_id == r.cfg->exit_id) {
            jumps_to_exit++;
        }
    }

    assert(jumps_to_exit >= 2);

    n00b_cfg_free(r.cfg);
    printf("  [PASS] cfg_return\n");
}

// ============================================================================
// Test 6: Switch creates case edges
// ============================================================================

static void
test_cfg_switch(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] cfg_switch\n");
        return;
    }

    const char *src =
        "void f(int x) {\n"
        "    switch (x) {\n"
        "        case 1: break;\n"
        "        case 2: break;\n"
        "    }\n"
        "}\n";

    cfg_result_t r = build_cfg_for(src);
    assert(r.cfg != NULL);

    assert(count_edges_of_kind(r.cfg, N00B_CFG_CASE_BRANCH) >= 1);

    n00b_cfg_free(r.cfg);
    printf("  [PASS] cfg_switch\n");
}

// ============================================================================
// Test 7: Successor/predecessor query
// ============================================================================

static void
test_cfg_successor_predecessor(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] cfg_successor_predecessor\n");
        return;
    }

    const char *src =
        "void f(int x) {\n"
        "    if (x) { int y; } else { int z; }\n"
        "}\n";

    cfg_result_t r = build_cfg_for(src);
    assert(r.cfg != NULL);

    // Entry block should have successors.
    n00b_list_t(n00b_cfg_edge_t) succs = n00b_cfg_successors(r.cfg, r.cfg->entry_id);
    assert(n00b_list_len(succs) > 0);
    n00b_list_free(succs);

    // Exit block should have predecessors.
    n00b_list_t(n00b_cfg_edge_t) preds = n00b_cfg_predecessors(r.cfg, r.cfg->exit_id);
    assert(n00b_list_len(preds) > 0);
    n00b_list_free(preds);

    n00b_cfg_free(r.cfg);
    printf("  [PASS] cfg_successor_predecessor\n");
}

// ============================================================================
// Test 8: Block count and edge count
// ============================================================================

static void
test_cfg_counts(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] cfg_counts\n");
        return;
    }

    const char *src = "void f(void) { }\n";

    cfg_result_t r = build_cfg_for(src);
    assert(r.cfg != NULL);

    // At minimum: entry + exit.
    assert(n00b_cfg_block_count(r.cfg) >= 2);
    // At minimum: entry -> exit fallthrough.
    assert(n00b_cfg_edge_count(r.cfg) >= 1);

    n00b_cfg_free(r.cfg);
    printf("  [PASS] cfg_counts\n");
}

// ============================================================================
// Test 9: Nested control flow
// ============================================================================

static void
test_cfg_nested(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] cfg_nested\n");
        return;
    }

    const char *src =
        "void f(int a) {\n"
        "    if (a) {\n"
        "        while (b) {\n"
        "            if (c) break;\n"
        "        }\n"
        "    }\n"
        "}\n";

    cfg_result_t r = build_cfg_for(src);
    assert(r.cfg != NULL);

    // Should have branch, loop, and jump edges.
    assert(count_edges_of_kind(r.cfg, N00B_CFG_BRANCH_TRUE) >= 2);
    assert(count_edges_of_kind(r.cfg, N00B_CFG_LOOP_BACK) >= 1);
    assert(count_edges_of_kind(r.cfg, N00B_CFG_JUMP) >= 1);

    n00b_cfg_free(r.cfg);
    printf("  [PASS] cfg_nested\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running cfg tests...\n");

    test_grammar_loads();
    test_cfg_linear();
    test_cfg_if_else();
    test_cfg_while();
    test_cfg_break_continue();
    test_cfg_return();
    test_cfg_switch();
    test_cfg_successor_predecessor();
    test_cfg_counts();
    test_cfg_nested();

    printf("All cfg tests passed.\n");
    n00b_shutdown();
    return 0;
}

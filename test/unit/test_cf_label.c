// test_cf_label.c — End-to-end integration tests for control flow labeling.
//
// Loads c_ncc.bnf, parses C source, runs the full annotation walk, and
// verifies that control flow labels are produced for annotated nodes.

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "test_portability.h"

#include "n00b.h"
#include "core/alloc.h"
#include "core/gc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "adt/option.h"
#include "parsers/scan_recipes.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "slay/annot_walk.h"
#include "slay/bnf.h"
#include "slay/cf_label.h"
#include "slay/grammar.h"
#include "slay/n00b_parse.h"
#include "slay/parse_tree.h"
#include "slay/symtab.h"
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

// This suite parses with the grammar's default backend (PWZ→Earley). Kept
// as a named constant for the diagnostic printouts below.
static const n00b_parse_mode_t current_mode = N00B_PARSE_MODE_DEFAULT;

static const char *
mode_name(n00b_parse_mode_t m)
{
    switch (m) {
    case N00B_PARSE_MODE_PWZ_ONLY:    return "pwz";
    case N00B_PARSE_MODE_EARLEY_ONLY: return "earley";
    default:                          return "default";
    }
}

// ============================================================================
// Label collection helper
// ============================================================================

typedef struct {
    int branch;
    int loop;
    int switch_ct;
    int jump;
    int capture;
    int assigns;
    int varref;
    int unwrap_result;
    int call;
} label_counts_t;

static void
count_labels_walk(n00b_cf_labels_t *cf_labels, n00b_parse_tree_t *node,
                  label_counts_t *out)
{
    if (!node) {
        return;
    }

    n00b_cf_label_t *lbl = n00b_cf_label_lookup(cf_labels, node);

    if (lbl) {
        switch (lbl->kind) {
        case N00B_CF_BRANCH:  out->branch++;    break;
        case N00B_CF_LOOP:    out->loop++;       break;
        case N00B_CF_SWITCH:  out->switch_ct++;  break;
        case N00B_CF_JUMP:    out->jump++;       break;
        case N00B_CF_CAPTURE: out->capture++;    break;
        case N00B_CF_ASSIGNS:       out->assigns++;        break;
        case N00B_CF_VARREF:        out->varref++;         break;
        case N00B_CF_UNWRAP_RESULT: out->unwrap_result++;  break;
        case N00B_CF_CALL:          out->call++;           break;
        }
    }

    if (n00b_tree_is_leaf(node)) {
        return;
    }

    size_t nc = n00b_tree_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        count_labels_walk(cf_labels, n00b_tree_child(node, i), out);
    }
}

static label_counts_t
count_labels_from_tree(n00b_annot_result_t *r, n00b_parse_tree_t *tree)
{
    label_counts_t counts = {0};

    if (!r || !r->cf_labels || !tree) {
        return counts;
    }

    count_labels_walk(r->cf_labels, tree, &counts);
    return counts;
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
// Test 1: Simple if
// ============================================================================

static void
test_simple_if(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] simple_if\n");
        return;
    }

    const char *src =
        "void f(void) {\n"
        "    if (x) { y(); }\n"
        "}\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    assert(tree != NULL);

    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);

    label_counts_t c = count_labels_from_tree(ar, tree);
    assert(c.branch == 1);
    assert(c.loop == 0);
    assert(c.jump == 0);

    n00b_symtab_free(ar->symtab);
    n00b_parse_result_free(r);
    printf("  [PASS] simple_if\n");
}

// ============================================================================
// Test 2: If-else
// ============================================================================

static void
test_if_else(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] if_else\n");
        return;
    }

    const char *src =
        "void f(void) {\n"
        "    if (x) { y(); } else { z(); }\n"
        "}\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);

    label_counts_t c = count_labels_from_tree(ar, tree);
    assert(c.branch == 1);

    // Verify the label has all three refs populated.
    // We need to find the branch label. Walk the tree to find it.
    // For now, just verify counts.

    n00b_symtab_free(ar->symtab);
    n00b_parse_result_free(r);
    printf("  [PASS] if_else\n");
}

// ============================================================================
// Test 3: While loop
// ============================================================================

static void
test_while_loop(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] while_loop\n");
        return;
    }

    const char *src =
        "void f(void) {\n"
        "    while (x) { y(); }\n"
        "}\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);

    label_counts_t c = count_labels_from_tree(ar, tree);
    assert(c.loop == 1);
    assert(c.branch == 0);

    n00b_symtab_free(ar->symtab);
    n00b_parse_result_free(r);
    printf("  [PASS] while_loop\n");
}

// ============================================================================
// Test 4: For loop
// ============================================================================

static void
test_for_loop(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] for_loop\n");
        return;
    }

    const char *src =
        "void f(void) {\n"
        "    int i;\n"
        "    for (i = 0; i < 10; i++) { x(); }\n"
        "}\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);

    label_counts_t c = count_labels_from_tree(ar, tree);
    assert(c.loop == 1);

    n00b_symtab_free(ar->symtab);
    n00b_parse_result_free(r);
    printf("  [PASS] for_loop\n");
}

// ============================================================================
// Test 5: Do-while loop
// ============================================================================

static void
test_do_while(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] do_while\n");
        return;
    }

    const char *src =
        "void f(void) {\n"
        "    do { x(); } while (y);\n"
        "}\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);

    label_counts_t c = count_labels_from_tree(ar, tree);
    assert(c.loop == 1);

    n00b_symtab_free(ar->symtab);
    n00b_parse_result_free(r);
    printf("  [PASS] do_while\n");
}

// ============================================================================
// Test 6: Switch
// ============================================================================

static void
test_switch(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] switch\n");
        return;
    }

    const char *src =
        "void f(int x) {\n"
        "    switch (x) {\n"
        "        case 1: break;\n"
        "    }\n"
        "}\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);

    label_counts_t c = count_labels_from_tree(ar, tree);
    assert(c.switch_ct == 1);
    assert(c.jump == 1); // break

    n00b_symtab_free(ar->symtab);
    n00b_parse_result_free(r);
    printf("  [PASS] switch\n");
}

// ============================================================================
// Test 7: Jump — return
// ============================================================================

static void
test_jump_return(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] jump_return\n");
        return;
    }

    const char *src = "void f(void) { return; }\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);

    label_counts_t c = count_labels_from_tree(ar, tree);
    assert(c.jump == 1);

    n00b_symtab_free(ar->symtab);
    n00b_parse_result_free(r);
    printf("  [PASS] jump_return\n");
}

static void
test_jump_return_value(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] jump_return_value\n");
        return;
    }

    const char *src = "int f(void) { return 0; }\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);

    label_counts_t c = count_labels_from_tree(ar, tree);
    assert(c.jump == 1);

    n00b_symtab_free(ar->symtab);
    n00b_parse_result_free(r);
    printf("  [PASS] jump_return_value\n");
}

// ============================================================================
// Test 8: Break + continue in loop
// ============================================================================

static void
test_jump_break_continue(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] jump_break_continue\n");
        return;
    }

    const char *src =
        "void f(void) {\n"
        "    while (1) {\n"
        "        if (x) break;\n"
        "        continue;\n"
        "    }\n"
        "}\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);

    label_counts_t c = count_labels_from_tree(ar, tree);
    assert(c.loop == 1);
    assert(c.branch == 1);
    assert(c.jump == 2); // break + continue

    n00b_symtab_free(ar->symtab);
    n00b_parse_result_free(r);
    printf("  [PASS] jump_break_continue\n");
}

// ============================================================================
// Test 9: Ternary
// ============================================================================

static void
test_ternary(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] ternary\n");
        return;
    }

    const char *src =
        "int f(int a, int b) {\n"
        "    return (a > b) ? a : b;\n"
        "}\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);

    label_counts_t c = count_labels_from_tree(ar, tree);
    assert(c.branch == 1); // ternary
    assert(c.jump == 1);   // return

    n00b_symtab_free(ar->symtab);
    n00b_parse_result_free(r);
    printf("  [PASS] ternary\n");
}

// ============================================================================
// Test 10: Nested control flow
// ============================================================================

static void
test_nested_control_flow(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] nested_control_flow\n");
        return;
    }

    const char *src =
        "void f(int a) {\n"
        "    if (a) {\n"
        "        while (b) {\n"
        "            if (c) break;\n"
        "            for (;;) { continue; }\n"
        "        }\n"
        "    } else {\n"
        "        return;\n"
        "    }\n"
        "}\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);

    label_counts_t c = count_labels_from_tree(ar, tree);
    assert(c.branch == 2);  // outer if + inner if
    assert(c.loop == 2);    // while + for
    assert(c.jump == 3);    // break + continue + return

    n00b_symtab_free(ar->symtab);
    n00b_parse_result_free(r);
    printf("  [PASS] nested_control_flow\n");
}

// ============================================================================
// Test 11: Symtab preserved alongside labels
// ============================================================================

static void
test_symtab_preserved(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] symtab_preserved\n");
        return;
    }

    const char *src =
        "typedef int MyInt;\n"
        "void f(void) { if (x) return; }\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);
    assert(ar->symtab != NULL);
    assert(ar->cf_labels != NULL);

    // CF labels should exist.
    label_counts_t c = count_labels_from_tree(ar, tree);
    assert(c.branch + c.jump > 0);

    n00b_symtab_free(ar->symtab);
    n00b_parse_result_free(r);
    printf("  [PASS] symtab_preserved\n");
}

// ============================================================================
// Test 12: Empty function — no labels
// ============================================================================

static void
test_empty_function(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] empty_function\n");
        return;
    }

    const char *src = "void f(void) { }\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);

    label_counts_t c = count_labels_from_tree(ar, tree);
    assert(c.branch == 0);
    assert(c.loop == 0);
    assert(c.switch_ct == 0);
    assert(c.jump == 0);

    n00b_symtab_free(ar->symtab);
    n00b_parse_result_free(r);
    printf("  [PASS] empty_function\n");
}

// ============================================================================
// Test 13: Struct ADT — tag symbol + adt_kind
// ============================================================================

static void
test_struct_adt(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] struct_adt\n");
        return;
    }

    const char *src =
        "struct foo { int x; };\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);

    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);
    assert(ar->symtab != NULL);

    // The tag "foo" should be in the "tag" namespace.
    n00b_sym_entry_t *sym = n00b_symtab_lookup(ar->symtab, r"tag", r"foo");
    assert(sym != NULL);
    assert(sym->kind == N00B_SYM_TAG);
    assert(sym->adt_kind->u8_bytes > 0);
    assert(n00b_unicode_str_eq(sym->adt_kind, r"struct"));

    // Field "x" is in a popped scope — should NOT be accessible at file level.
    n00b_sym_entry_t *field = n00b_symtab_lookup(ar->symtab, r"", r"x");
    assert(field == NULL);

    n00b_symtab_free(ar->symtab);
    n00b_parse_result_free(r);
    printf("  [PASS] struct_adt\n");
}

// ============================================================================
// Test 14: Anonymous struct — no tag, no crash
// ============================================================================

static void
test_anonymous_struct(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] anonymous_struct\n");
        return;
    }

    const char *src =
        "struct { int x; } anon_var;\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);

    // No tag name registered for anonymous struct — that's fine.
    // Just verify the walk didn't crash and symtab exists.
    assert(ar->symtab != NULL);

    n00b_symtab_free(ar->symtab);
    n00b_parse_result_free(r);
    printf("  [PASS] anonymous_struct\n");
}

// ============================================================================
// Test 15: Enum ADT — tag symbol + fields
// ============================================================================

static void
test_enum_adt(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] enum_adt\n");
        return;
    }

    const char *src =
        "enum color { RED, GREEN, BLUE };\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);
    assert(ar->symtab != NULL);

    // The tag "color" should be in the "tag" namespace.
    n00b_sym_entry_t *sym = n00b_symtab_lookup(ar->symtab, r"tag", r"color");
    assert(sym != NULL);
    assert(sym->kind == N00B_SYM_TAG);
    assert(sym->adt_kind->u8_bytes > 0);
    assert(n00b_unicode_str_eq(sym->adt_kind, r"enum"));

    // Enum constants are fields in a popped scope — not accessible at file level.
    assert(n00b_symtab_lookup(ar->symtab, r"", r"RED") == NULL);
    assert(n00b_symtab_lookup(ar->symtab, r"", r"GREEN") == NULL);
    assert(n00b_symtab_lookup(ar->symtab, r"", r"BLUE") == NULL);

    n00b_symtab_free(ar->symtab);
    n00b_parse_result_free(r);
    printf("  [PASS] enum_adt\n");
}

// ============================================================================
// Test 16: Union ADT — tag symbol
// ============================================================================

static void
test_union_adt(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] union_adt\n");
        return;
    }

    const char *src =
        "union data { int i; float f; };\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);
    assert(ar->symtab != NULL);

    // The tag "data" should be in the "tag" namespace.
    n00b_sym_entry_t *sym = n00b_symtab_lookup(ar->symtab, r"tag", r"data");
    assert(sym != NULL);
    assert(sym->kind == N00B_SYM_TAG);
    assert(sym->adt_kind->u8_bytes > 0);
    assert(n00b_unicode_str_eq(sym->adt_kind, r"union"));

    n00b_symtab_free(ar->symtab);
    n00b_parse_result_free(r);
    printf("  [PASS] union_adt\n");
}

// ============================================================================
// ============================================================================
// Test 17: Struct with typedef still works
// ============================================================================

static void
test_struct_with_typedef(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] struct_with_typedef\n");
        return;
    }

    const char *src =
        "typedef struct point { int x; int y; } point_t;\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);
    assert(ar->symtab != NULL);

    // Tag "point" in "tag" namespace with adt_kind "struct".
    n00b_sym_entry_t *tag = n00b_symtab_lookup(ar->symtab, r"tag", r"point");
    assert(tag != NULL);
    assert(tag->kind == N00B_SYM_TAG);
    assert(tag->adt_kind->u8_bytes > 0);
    assert(n00b_unicode_str_eq(tag->adt_kind, r"struct"));

    // "point_t" should be found in the default namespace via @declares.
    n00b_sym_entry_t *td = n00b_symtab_lookup_all(ar->symtab, r"", r"point_t");
    assert(td != NULL);
    assert(td->kind == N00B_SYM_VARIABLE);  // @declares registers as variable

    n00b_symtab_free(ar->symtab);
    n00b_parse_result_free(r);
    printf("  [PASS] struct_with_typedef\n");
}

// ============================================================================
// Test 18: Forward-declared struct (no body) — no ADT annotation
// ============================================================================

static void
test_forward_struct(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] forward_struct\n");
        return;
    }

    const char *src =
        "struct fwd;\n"
        "void f(struct fwd *p) { }\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);

    // Forward declarations use the non-annotated rule — no tag symbol
    // should be registered (the @adt annotation is only on definition rules).
    // Walk should not crash.
    assert(ar->symtab != NULL);

    n00b_symtab_free(ar->symtab);
    n00b_parse_result_free(r);
    printf("  [PASS] forward_struct\n");
}

// ============================================================================
// Test 19: Earley group normalization — no group_item nodes in tree
// ============================================================================

static bool
tree_has_group_item(n00b_parse_tree_t *t)
{
    if (!t || n00b_tree_is_leaf(t)) {
        return false;
    }

    n00b_nt_node_t *pn = &n00b_tree_node_value(t);

    if (pn->group_item) {
        return true;
    }

    size_t nc = n00b_tree_num_children(t);

    for (size_t i = 0; i < nc; i++) {
        if (tree_has_group_item(n00b_tree_child(t, i))) {
            return true;
        }
    }

    return false;
}

static void
test_earley_no_group_items(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] earley_no_group_items\n");
        return;
    }

    // Only meaningful for earley mode — group_item nodes are earley-specific.
    if (current_mode != N00B_PARSE_MODE_EARLEY_ONLY) {
        printf("  [SKIP] earley_no_group_items (pwz mode)\n");
        return;
    }

    const char *src =
        "struct bar { int a; char b; };\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    assert(tree != NULL);

    // After normalization, no group_item wrappers should remain.
    assert(!tree_has_group_item(tree));

    // The annotation walk should still find the tag.
    n00b_annot_result_t *ar = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);

    n00b_sym_entry_t *sym = n00b_symtab_lookup(ar->symtab, r"tag", r"bar");
    assert(sym != NULL);
    assert(sym->kind == N00B_SYM_TAG);
    assert(n00b_unicode_str_eq(sym->adt_kind, r"struct"));

    n00b_symtab_free(ar->symtab);
    n00b_parse_result_free(r);
    printf("  [PASS] earley_no_group_items\n");
}

// ============================================================================
// main
// ============================================================================

static void
run_all_tests(void)
{
    test_simple_if();
    test_if_else();
    test_while_loop();
    test_for_loop();
    test_do_while();
    test_switch();
    test_jump_return();
    test_jump_return_value();
    test_jump_break_continue();
    test_ternary();
    test_nested_control_flow();
    test_symtab_preserved();
    test_empty_function();
    test_struct_adt();
    test_anonymous_struct();
    test_enum_adt();
    test_union_adt();
    test_struct_with_typedef();
    test_forward_struct();
    test_earley_no_group_items();
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running cf_label tests...\n");

    test_grammar_loads();

    // Run in default mode only. Earley is for error diagnostics on
    // failed parses — not for producing trees that feed annotation walks.
    printf("  --- parser: %s ---\n", mode_name(current_mode));
    run_all_tests();

    printf("All cf_label tests passed.\n");
    n00b_shutdown();
    return 0;
}

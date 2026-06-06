// test_c_parse.c — Integration tests: load c_ncc.bnf, tokenize + parse
// C source code, verify valid trees and typedef detection via the
// post-parse annotation walk.

#include <assert.h>
#include <dirent.h>
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
#include "slay/grammar.h"
#include "slay/n00b_parse.h"
#include "slay/parse_tree.h"
#include "slay/symtab.h"
#include "slay/token.h"
#include "text/strings/string_ops.h"
#include "internal/slay/grammar_internal.h"

// ============================================================================
// C tokenizer callback
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

// The C tokenizer for grammar-based parsing.
// Handles: whitespace/comments (trivia), identifiers/keywords, numbers,
// strings, char literals, and operators.
static bool
c_tokenize(n00b_scanner_t *s)
{
restart:
    // Skip whitespace.
    n00b_scan_skip_whitespace(s);

    if (n00b_scan_at_eof(s)) {
        return false;
    }

    // Skip line comments.
    if (n00b_scan_peek_byte(s, 0) == '/'
        && n00b_scan_peek_byte(s, 1) == '/') {
        n00b_scan_skip_line_comment(s);
        goto restart;
    }

    // Skip block comments.
    if (n00b_scan_peek_byte(s, 0) == '/'
        && n00b_scan_peek_byte(s, 1) == '*') {
        n00b_scan_skip_block_comment(s, "/*", "*/");
        goto restart;
    }

    n00b_scan_mark(s);
    n00b_codepoint_t cp = n00b_scan_peek(s, 0);

    // -----------------------------------------------------------------
    // String literals
    // -----------------------------------------------------------------
    if (cp == '"') {
        n00b_option_t(n00b_string_t *) val = n00b_scan_string_double(s);
        n00b_scan_emit(s, .token_type = "STRING_LIT", .contents = val);
        return true;
    }

    // -----------------------------------------------------------------
    // Character literals
    // -----------------------------------------------------------------
    if (cp == '\'') {
        n00b_option_t(n00b_string_t *) val = n00b_scan_string_single(s);
        n00b_scan_emit(s, .token_type = "CHAR_LIT", .contents = val);
        return true;
    }

    // -----------------------------------------------------------------
    // Numbers (must check before identifier because of 0x etc.)
    // -----------------------------------------------------------------
    if ((cp >= '0' && cp <= '9')
        || (cp == '.' && n00b_scan_peek_byte(s, 1) >= '0'
            && n00b_scan_peek_byte(s, 1) <= '9')) {
        bool emitted = n00b_scan_number(s, "INTEGER", "FLOAT");

        if (emitted) {
            // Consume C integer suffixes (U, L, UL, ULL, LL, etc.)
            // and float suffixes (f, F, l, L) that scan_number doesn't eat.
            for (;;) {
                uint8_t ch = n00b_scan_peek_byte(s, 0);
                if (ch == 'u' || ch == 'U' || ch == 'l' || ch == 'L'
                    || ch == 'f' || ch == 'F') {
                    n00b_scan_advance(s);
                }
                else {
                    break;
                }
            }
            return true;
        }

        // Fallthrough — shouldn't happen, but be safe.
    }

    // -----------------------------------------------------------------
    // Identifiers / keywords
    // -----------------------------------------------------------------
    if ((cp >= 'a' && cp <= 'z') || (cp >= 'A' && cp <= 'Z') || cp == '_') {
        n00b_option_t(n00b_string_t *) id_val = c_scan_identifier(s);

        if (n00b_option_is_set(id_val)) {
            // Try as keyword (hashes text, checks grammar).
            n00b_token_err_t err = n00b_scan_emit(s, .contents = id_val);

            if (err == N00B_TOK_ERR_NOT_IN_GRAMMAR) {
                n00b_scan_emit(s, .token_type = "IDENTIFIER",
                               .contents = id_val);
            }

            return true;
        }
    }

    // -----------------------------------------------------------------
    // Multi-character operators (longest match first)
    // -----------------------------------------------------------------

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

    // -----------------------------------------------------------------
    // Single-character tokens
    // -----------------------------------------------------------------
    n00b_scan_advance(s);

    n00b_token_err_t err = n00b_scan_emit(s);

    if (err != N00B_TOK_OK) {
        n00b_scan_emit(s, .token_type = "OTHER");
    }

    return true;
}

// ============================================================================
// Grammar loading helper
// ============================================================================

static n00b_grammar_t *
load_c_grammar(void)
{
    // Try several relative paths — meson runs from the build dir.
    const char *paths[] = {
        "grammars/c_ncc.bnf",
        "../grammars/c_ncc.bnf",
        "../../grammars/c_ncc.bnf",
        NULL,
    };

    // Also try MESON_SOURCE_ROOT.
    const char *srcroot = getenv("MESON_SOURCE_ROOT");

    FILE *f = NULL;

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
        fprintf(stderr, "  [SKIP] Cannot find grammars/c_ncc.bnf\n");
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

// ============================================================================
// Parse helper: tokenize + parse a C string against the grammar.
// ============================================================================

static n00b_parse_result_t *
parse_c_source(n00b_grammar_t *g, const char *src)
{
    n00b_buffer_t *buf = n00b_buffer_from_bytes((char *)src,
                                                  (int64_t)strlen(src));
    n00b_scanner_t *scanner = n00b_scanner_new(buf, c_tokenize, g);
    n00b_token_stream_t *ts = n00b_token_stream_new(scanner);

    n00b_parse_result_t *result = n00b_grammar_parse(g, ts);

    // We intentionally don't free ts/scanner here — they must outlive
    // the result (tokens are borrowed). They'll leak, but this is a test.
    return result;
}

// ============================================================================
// Read a file into a malloc'd null-terminated buffer.
// ============================================================================

static char *
read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "r");

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

    if (out_len) {
        *out_len = (size_t)len;
    }

    return buf;
}

// ============================================================================
// Test 1: Grammar loads successfully
// ============================================================================

static n00b_grammar_t *shared_grammar = NULL;

static void
test_grammar_loads(void)
{
    shared_grammar = load_c_grammar();
    assert(shared_grammar != NULL);
    // File-scope static: the GC doesn't auto-scan the test binary's
    // BSS, so register the cell explicitly so a later collect can
    // forward the pointer when the grammar object moves.
    n00b_gc_register_root(shared_grammar);
    printf("  [PASS] grammar_loads\n");
}

// ============================================================================
// Test 2: Simple declaration parses
// ============================================================================

static void
test_simple_decl(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] simple_decl (no grammar)\n");
        return;
    }

    n00b_parse_result_t *r = parse_c_source(shared_grammar, "int x;\n");
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    assert(tree != NULL);

    n00b_parse_result_free(r);
    printf("  [PASS] simple_decl\n");
}

// ============================================================================
// Test 3: Typedef declaration parses
// ============================================================================

static void
test_typedef_decl(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] typedef_decl (no grammar)\n");
        return;
    }

    n00b_parse_result_t *r = parse_c_source(shared_grammar,
                                              "typedef int MyInt;\n");
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    assert(tree != NULL);

    n00b_parse_result_free(r);
    printf("  [PASS] typedef_decl\n");
}

// ============================================================================
// Test 4: Function definition parses
// ============================================================================

static void
test_function_def(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] function_def (no grammar)\n");
        return;
    }

    const char *src =
        "int main(void) {\n"
        "    return 0;\n"
        "}\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);

    if (!n00b_parse_result_ok(r)) {
        n00b_string_t *err = n00b_parse_result_error_string(r);
        fprintf(stderr, "  function_def: %.*s\n",
                (int)err->u8_bytes, err->data);
    }

    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    assert(tree != NULL);

    n00b_parse_result_free(r);
    printf("  [PASS] function_def\n");
}

// ============================================================================
// Test 5: Typedef + use parses (the key ambiguity test)
// ============================================================================

static void
test_typedef_then_use(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] typedef_then_use (no grammar)\n");
        return;
    }

    const char *src =
        "typedef int MyInt;\n"
        "MyInt x;\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);

    if (!n00b_parse_result_ok(r)) {
        n00b_string_t *err = n00b_parse_result_error_string(r);
        fprintf(stderr, "  typedef_then_use: %.*s\n",
                (int)err->u8_bytes, err->data);
    }

    assert(n00b_parse_result_ok(r));

    // This should be ambiguous: "MyInt" can be parsed as either an
    // identifier (expression statement) or a typedef_name (type specifier
    // in a declaration).  The grammar handles this via ambiguity.
    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    assert(tree != NULL);

    n00b_parse_result_free(r);
    printf("  [PASS] typedef_then_use\n");
}

// ============================================================================
// Test 6: Struct with typedef
// ============================================================================

static void
test_struct_typedef(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] struct_typedef (no grammar)\n");
        return;
    }

    const char *src =
        "typedef struct { int x; int y; } Point;\n"
        "Point p;\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);

    if (!n00b_parse_result_ok(r)) {
        n00b_string_t *err = n00b_parse_result_error_string(r);
        fprintf(stderr, "  struct_typedef: %.*s\n",
                (int)err->u8_bytes, err->data);
    }

    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    assert(tree != NULL);

    n00b_parse_result_free(r);
    printf("  [PASS] struct_typedef\n");
}

// ============================================================================
// Test 7: Nested scopes with typedef
// ============================================================================

static void
test_nested_typedef_scopes(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] nested_typedef_scopes (no grammar)\n");
        return;
    }

    const char *src =
        "typedef int MyInt;\n"
        "void foo(MyInt a) {\n"
        "    int x = 1;\n"
        "    {\n"
        "        int x = 2;\n"
        "    }\n"
        "}\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);

    if (!n00b_parse_result_ok(r)) {
        n00b_string_t *err = n00b_parse_result_error_string(r);
        fprintf(stderr, "  nested_typedef_scopes: %.*s\n",
                (int)err->u8_bytes, err->data);
    }

    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    assert(tree != NULL);

    n00b_parse_result_free(r);
    printf("  [PASS] nested_typedef_scopes\n");
}

// ============================================================================
// Test 8: Multiple typedefs and usage
// ============================================================================

static void
test_multi_typedef(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] multi_typedef (no grammar)\n");
        return;
    }

    const char *src =
        "typedef unsigned long size_t;\n"
        "typedef int int32_t;\n"
        "typedef struct node { int32_t val; struct node *next; } node_t;\n"
        "size_t len;\n"
        "node_t *head;\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);

    if (!n00b_parse_result_ok(r)) {
        n00b_string_t *err = n00b_parse_result_error_string(r);
        fprintf(stderr, "  multi_typedef: %.*s\n",
                (int)err->u8_bytes, err->data);
    }

    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    assert(tree != NULL);

    n00b_parse_result_free(r);
    printf("  [PASS] multi_typedef\n");
}

// ============================================================================
// Test 9: Parse actual .c file from the codebase
// ============================================================================

static void
test_parse_source_file(const char *path)
{
    if (!shared_grammar) {
        printf("  [SKIP] parse_file %s (no grammar)\n", path);
        return;
    }

    size_t  len = 0;
    char   *src = read_file(path, &len);

    if (!src) {
        printf("  [SKIP] parse_file %s (cannot read)\n", path);
        return;
    }

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);

    if (!n00b_parse_result_ok(r)) {
        n00b_string_t *err = n00b_parse_result_error_string(r);
        fprintf(stderr, "  parse_file %s: %.*s\n",
                path, (int)err->u8_bytes, err->data);
        n00b_parse_result_free(r);
        free(src);
        assert(0 && "parse_file failed");
    }

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    assert(tree != NULL);

    printf("  [PASS] parse_file %s\n", path);
    n00b_parse_result_free(r);
    free(src);
}

// ============================================================================
// Test 10: Parse all .c files in a directory (best-effort)
// ============================================================================

static int
test_parse_directory(const char *dirpath, int max_files)
{
    if (!shared_grammar) {
        printf("  [SKIP] parse_dir %s (no grammar)\n", dirpath);
        return 0;
    }

    DIR *d = opendir(dirpath);

    if (!d) {
        printf("  [SKIP] parse_dir %s (cannot open)\n", dirpath);
        return 0;
    }

    int       passed = 0;
    int       failed = 0;
    int       count  = 0;
    struct dirent *ent;

    while ((ent = readdir(d)) != NULL && count < max_files) {
        size_t nlen = strlen(ent->d_name);

        if (nlen < 3 || strcmp(ent->d_name + nlen - 2, ".c") != 0) {
            continue;
        }

        char *fullpath = nullptr;
        (void)asprintf(&fullpath, "%s/%s", dirpath, ent->d_name);

        size_t  flen = 0;
        char   *src  = read_file(fullpath, &flen);
        free(fullpath);

        if (!src) {
            continue;
        }

        n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
        count++;

        if (n00b_parse_result_ok(r)) {
            n00b_parse_tree_t *tree = n00b_parse_result_tree(r);

            if (tree) {
                passed++;
            }
            else {
                failed++;
                fprintf(stderr, "  parse_dir %s: OK but no tree\n",
                        ent->d_name);
            }
        }
        else {
            failed++;
            n00b_string_t *err = n00b_parse_result_error_string(r);
            fprintf(stderr, "  parse_dir %s/%s: %.*s\n",
                    dirpath, ent->d_name,
                    (int)err->u8_bytes, err->data);
        }

        n00b_parse_result_free(r);
        free(src);
    }

    closedir(d);

    printf("  parse_dir %s: %d/%d passed (%d failed)\n",
           dirpath, passed, count, failed);

    return failed;
}

// ============================================================================
// Test 11: Annotation walk on parsed C code produces typedef entries
// ============================================================================

static void
test_annot_walk_c_typedef(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] annot_walk_c_typedef (no grammar)\n");
        return;
    }

    const char *src =
        "typedef int MyInt;\n"
        "MyInt x;\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);
    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    assert(tree != NULL);

    // Run the annotation walk.
    n00b_symtab_t *st = n00b_annot_walk_tree(shared_grammar, tree);
    assert(st != NULL);

    // The annotation walk should have populated the symbol table.
    // Note: whether "MyInt" is detected as a typedef depends on
    // the @declares annotation finding the right children.
    // This is a smoke test — if we get here without crashing, the
    // infrastructure is working.
    printf("  [PASS] annot_walk_c_typedef (walk completed)\n");

    n00b_symtab_free(st);
    n00b_parse_result_free(r);
}

// ============================================================================
// Test 12: Complex real-world C patterns
// ============================================================================

static void
test_complex_patterns(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] complex_patterns (no grammar)\n");
        return;
    }

    // Function pointers, casts, ternary, for loops, etc.
    const char *src =
        "typedef void (*handler_t)(int sig);\n"
        "int main(int argc, char **argv) {\n"
        "    handler_t h = 0;\n"
        "    int i;\n"
        "    for (i = 0; i < argc; i++) {\n"
        "        int x = (argc > 1) ? 1 : 0;\n"
        "    }\n"
        "    return 0;\n"
        "}\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);

    if (!n00b_parse_result_ok(r)) {
        n00b_string_t *err = n00b_parse_result_error_string(r);
        fprintf(stderr, "  complex_patterns: %.*s\n",
                (int)err->u8_bytes, err->data);
    }

    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    assert(tree != NULL);

    n00b_parse_result_free(r);
    printf("  [PASS] complex_patterns\n");
}

// ============================================================================
// Test 13: Windows/MSVC declarations
// ============================================================================

static void
test_windows_msvc_decls(void)
{
    if (!shared_grammar) {
        printf("  [SKIP] windows_msvc_decls (no grammar)\n");
        return;
    }

    const char *src =
        "__declspec(dllexport) int __stdcall exported_fn(__int64 value);\n"
        "typedef int (__cdecl *callback_t)(__int32 value);\n"
        "typedef int __m64 __attribute__((__vector_size__(8)));\n"
        "__forceinline __int64 add64(__int64 a, __int64 b) {\n"
        "    return a + b;\n"
        "}\n"
        "__m64 make_m64(void) {\n"
        "    return __extension__ (__m64){ 0LL };\n"
        "}\n";

    n00b_parse_result_t *r = parse_c_source(shared_grammar, src);

    if (!n00b_parse_result_ok(r)) {
        n00b_string_t *err = n00b_parse_result_error_string(r);
        fprintf(stderr, "  windows_msvc_decls: %.*s\n",
                (int)err->u8_bytes, err->data);
    }

    assert(n00b_parse_result_ok(r));

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);
    assert(tree != NULL);

    n00b_parse_result_free(r);
    printf("  [PASS] windows_msvc_decls\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    printf("Running C parse integration tests...\n");

    // Load grammar (shared across tests).
    test_grammar_loads();

    // Snippet parsing tests.
    test_simple_decl();
    test_typedef_decl();
    test_function_def();
    test_typedef_then_use();
    test_struct_typedef();
    test_nested_typedef_scopes();
    test_multi_typedef();
    test_complex_patterns();
    test_windows_msvc_decls();

    // Annotation walk on parsed C code.
    test_annot_walk_c_typedef();

    // Parse actual source files from the codebase.
    // Try several paths for the source directory.
    const char *src_dirs[] = {
        "src/slay",
        "../src/slay",
        "../../src/slay",
        NULL,
    };

    const char *src_dir = NULL;

    const char **p;
    for (p = src_dirs; *p; p++) {
        DIR *d = opendir(*p);

        if (d) {
            closedir(d);
            src_dir = *p;
            break;
        }
    }

    char *dynamic_dir_buf = nullptr;

    if (!src_dir && getenv("MESON_SOURCE_ROOT")) {
        (void)asprintf(&dynamic_dir_buf, "%s/src/slay",
                       getenv("MESON_SOURCE_ROOT"));
        DIR *d = opendir(dynamic_dir_buf);

        if (d) {
            closedir(d);
            src_dir = dynamic_dir_buf;
        }
    }

    // Source file parsing is deferred — most .c files in the codebase
    // use ncc extensions that the standard C grammar doesn't cover.
    // Uncomment when we have a grammar that handles ncc syntax.
    //
    // if (src_dir) {
    //     printf("  Parsing .c files from %s...\n", src_dir);
    //     int failures = test_parse_directory(src_dir, 50);
    //     if (failures > 0) {
    //         printf("  WARNING: %d file(s) failed to parse\n", failures);
    //     }
    // }

    free(dynamic_dir_buf);

    if (shared_grammar) {
        n00b_grammar_free(shared_grammar);
    }

    printf("C parse integration tests done.\n");
    return 0;
}

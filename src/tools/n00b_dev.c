// n00b_dev.c — Development tool for parsing n00b source files.
//
// Loads the n00b grammar, tokenizes an input file, parses it, runs
// the annotation walk, and prints the annotated parse tree.
//
// Usage: n00b_dev <source-file> [--earley | --pwz | --tokens | --grammar]

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "slay/annot_walk.h"
#include "slay/codegen.h"
#include "n00b/embed.h"
#include "n00b/embed_ffi.h"
#include "n00b/n00b_compile.h"
#include "n00b/n00b_type_map.h"
#include "slay/bnf.h"
#include "slay/cf_label.h"
#include "slay/cdg.h"
#include "slay/cfg.h"
#include "slay/dfg.h"
#include "slay/debug.h"
#include "slay/grammar.h"
#include "slay/earley.h"
#include "slay/n00b_parse.h"
#include "n00b/n00b_tokenizer.h"
#include "slay/parse_tree.h"
#include "slay/symtab.h"
#include "slay/token.h"
#include "slay/diagnostic.h"
#include "slay/analyze.h"
#include "internal/slay/earley_internal.h"
#include "typecheck/types.h"
#include "typecheck/print.h"

// From n00b_repl.c.
extern int  n00b_repl_run(n00b_grammar_t *grammar);
extern bool n00b_load_builtins(n00b_grammar_t *g, n00b_cg_session_t *session);

// ============================================================================
// Grammar loading
// ============================================================================

static n00b_grammar_t *
load_n00b_grammar(const char *grammar_file, n00b_parse_mode_t parse_mode)
{
    FILE *f = NULL;

    if (grammar_file) {
        f = fopen(grammar_file, "r");

        if (!f) {
            fprintf(stderr, "error: cannot open grammar file '%s'\n",
                    grammar_file);
            return NULL;
        }
    }
    else {
        const char *paths[] = {
            "grammars/n00b.bnf",
            "../grammars/n00b.bnf",
            "../../grammars/n00b.bnf",
            NULL,
        };

        const char *srcroot = getenv("MESON_SOURCE_ROOT");

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
            fprintf(stderr, "error: cannot find grammars/n00b.bnf\n");
            return NULL;
        }
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = n00b_alloc_array(char, (size_t)len + 1);
    fread(buf, 1, (size_t)len, f);
    buf[len] = '\0';
    fclose(f);

    n00b_string_t *bnf_text = n00b_string_from_cstr(buf);

    // Backend selection is fixed at instantiation (chosen from CLI flags);
    // error recovery off.
    n00b_grammar_t *g = n00b_grammar_new(.parse_mode     = parse_mode,
                                         .error_recovery = false);

    bool ok = n00b_bnf_load(bnf_text, r"module", g);

    if (!ok) {
        fprintf(stderr, "error: n00b_bnf_load failed\n");
        n00b_grammar_free(g);
        return NULL;
    }

    return g;
}

// ============================================================================
// Source file reading
// ============================================================================

static char *
read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "r");

    if (!f) {
        fprintf(stderr, "error: cannot open '%s'\n", path);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = n00b_alloc_array(char, (size_t)len + 1);
    fread(buf, 1, (size_t)len, f);
    buf[len] = '\0';
    fclose(f);

    *out_len = (size_t)len;
    return buf;
}

// ============================================================================
// Token dumping
// ============================================================================

static void
dump_tokens(n00b_token_stream_t *ts)
{
    int index = 0;

    while (true) {
        n00b_token_info_t *tok = n00b_stream_next(ts);

        if (!tok || tok->tid == N00B_TOK_EOF) {
            break;
        }

        const char *text = "";
        size_t      tlen = 0;

        if (n00b_option_is_set(tok->value)) {
            n00b_string_t *val = n00b_option_get(tok->value);
            text = val->data;
            tlen = val->u8_bytes;
        }

        printf("%4d  tid=%-20lld L%u:C%u  \"%.*s\"\n",
               index++, (long long)tok->tid, tok->line, tok->column,
               (int)tlen, text);
    }
}

// ============================================================================
// Symbol table dumping
// ============================================================================

static const char *
sym_kind_str(n00b_sym_kind_t kind)
{
    switch (kind) {
    case N00B_SYM_VARIABLE:   return "var";
    case N00B_SYM_FUNCTION:   return "func";
    case N00B_SYM_TYPEDEF:    return "type";
    case N00B_SYM_TAG:        return "tag";
    case N00B_SYM_ENUM_CONST: return "enum";
    case N00B_SYM_LABEL:      return "label";
    case N00B_SYM_PARAM:      return "param";
    default:                  return "?";
    }
}

static void
dump_symtab_recursive(n00b_parse_tree_t *t, int depth)
{
    if (!t || n00b_tree_is_leaf(t)) {
        return;
    }

    n00b_nt_node_t *pn = &n00b_tree_node_value(t);

    if (pn->scope) {
        n00b_scope_t *scope = pn->scope;
        int indent = scope->depth;

        for (int i = 0; i < indent; i++) {
            printf("  ");
        }

        if (scope->name && scope->name->data && scope->name->u8_bytes > 0) {
            printf("scope \"%.*s\" (depth %d):\n",
                   (int)scope->name->u8_bytes, scope->name->data,
                   scope->depth);
        }
        else {
            printf("scope (depth %d):\n", scope->depth);
        }

        n00b_sym_entry_t *entry = scope->first_in_scope;

        while (entry) {
            for (int i = 0; i < indent + 1; i++) {
                printf("  ");
            }

            uint32_t line = 0;

            if (entry->decl_node) {
                n00b_parse_tree_t *first = n00b_pt_first_token(entry->decl_node);

                if (first) {
                    n00b_token_info_t *tok = n00b_parse_node_token(first);

                    if (tok) {
                        line = tok->line;
                    }
                }
            }

            if (entry->type_var) {
                n00b_string_t *ts = n00b_tc_type_to_string(entry->type_var);
                printf("%-6s %.*s : %.*s  line %u",
                       sym_kind_str(entry->kind),
                       (int)entry->name->u8_bytes, entry->name->data,
                       (int)ts->u8_bytes, ts->data,
                       line);
            }
            else {
                printf("%-6s %.*s  line %u",
                       sym_kind_str(entry->kind),
                       (int)entry->name->u8_bytes, entry->name->data,
                       line);
            }

            if (entry->exposed_scope) {
                n00b_scope_t *es = entry->exposed_scope;

                if (es->name && es->name->data && es->name->u8_bytes > 0) {
                    printf("  [exposes \"%.*s\"]",
                           (int)es->name->u8_bytes, es->name->data);
                }
                else {
                    printf("  [exposes scope]");
                }
            }

            printf("\n");

            entry = entry->next_in_scope;
        }
    }

    size_t nc = n00b_tree_num_children(t);

    for (size_t i = 0; i < nc; i++) {
        dump_symtab_recursive(n00b_tree_child(t, i), depth + 1);
    }
}

static void
dump_symtab(n00b_parse_tree_t *tree)
{
    dump_symtab_recursive(tree, 0);
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    bool                show_tokens  = false;
    bool                show_grammar = false;
    bool                show_states  = false;
    bool                show_lr0     = false;
    bool                show_cfg     = false;
    bool                show_cdg     = false;
    bool                show_dfg     = false;
    bool                show_labels  = false;
    bool                show_symtab  = false;
    bool                run_analyze  = false;
    bool                run_typecheck = false;
    bool                repl_mode    = false;
    bool                run_mode     = false;
    bool                quiet        = false;
    n00b_parse_mode_t   mode         = N00B_PARSE_MODE_DEFAULT;
    const char         *source_file  = NULL;
    const char         *grammar_file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--earley") == 0) {
            mode = N00B_PARSE_MODE_EARLEY_ONLY;
        }
        else if (strcmp(argv[i], "--pwz") == 0) {
            mode = N00B_PARSE_MODE_PWZ_ONLY;
        }
        else if (strcmp(argv[i], "--tokens") == 0) {
            show_tokens = true;
        }
        else if (strcmp(argv[i], "--grammar") == 0) {
            show_grammar = true;
        }
        else if (strcmp(argv[i], "--states") == 0) {
            show_states = true;
        }
        else if (strcmp(argv[i], "--lr0") == 0) {
            show_lr0 = true;
        }
        else if (strcmp(argv[i], "--cfg") == 0) {
            show_cfg = true;
        }
        else if (strcmp(argv[i], "--cdg") == 0) {
            show_cdg = true;
        }
        else if (strcmp(argv[i], "--dfg") == 0) {
            show_dfg = true;
        }
        else if (strcmp(argv[i], "--labels") == 0) {
            show_labels = true;
        }
        else if (strcmp(argv[i], "--symtab") == 0
                 || strcmp(argv[i], "-s") == 0) {
            show_symtab = true;
        }
        else if (strcmp(argv[i], "--analyze") == 0
                 || strcmp(argv[i], "-a") == 0) {
            run_analyze = true;
        }
        else if (strcmp(argv[i], "--typecheck") == 0
                 || strcmp(argv[i], "-t") == 0) {
            run_typecheck = true;
        }
        else if (strcmp(argv[i], "--all") == 0) {
            show_cfg      = true;
            show_cdg      = true;
            show_dfg      = true;
            show_symtab   = true;
            run_analyze   = true;
            run_typecheck = true;
        }
        else if (strcmp(argv[i], "--repl") == 0) {
            repl_mode = true;
        }
        else if (strcmp(argv[i], "--run") == 0) {
            run_mode = true;
        }
        else if (strcmp(argv[i], "--quiet") == 0
                 || strcmp(argv[i], "-q") == 0) {
            quiet = true;
        }
        else if (strcmp(argv[i], "--grammar-file") == 0) {
            if (i + 1 < argc) {
                grammar_file = argv[++i];
            }
            else {
                fprintf(stderr, "--grammar-file requires an argument\n");
                return 1;
            }
        }
        else if (argv[i][0] == '-') {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            return 1;
        }
        else {
            source_file = argv[i];
        }
    }

    if (!source_file && !repl_mode) {
        fprintf(stderr, "usage: n00b_dev <source-file> "
                        "[--earley|--pwz] [--tokens] [--grammar] "
                        "[--cfg] [--cdg] [--dfg] [--labels] [--symtab|-s] "
                        "[--analyze|-a] [--typecheck|-t] [--all] "
                        "[--quiet|-q] [--repl] [--run] "
                        "[--grammar-file <path>]\n");
        return 1;
    }

    // Load grammar (backend selection fixed at instantiation from flags).
    n00b_grammar_t *g = load_n00b_grammar(grammar_file, mode);

    if (!g) {
        return 1;
    }

    // REPL mode: enter interactive loop.
    if (repl_mode) {
        int rc = n00b_repl_run(g);
        n00b_shutdown();
        return rc;
    }

    if (show_grammar) {
        printf("=== Grammar ===\n");
        n00b_grammar_print(g, stdout);
        printf("\n");
    }

    if (show_lr0) {
        printf("=== LR(0) Table ===\n");
        n00b_lr0_print(g, stdout);
        printf("\n");
    }

    // Read source.
    size_t src_len;
    char  *src = read_file(source_file, &src_len);

    if (!src) {
        return 1;
    }

    // Tokenize.
    n00b_buffer_t       *buf     = n00b_buffer_from_bytes(src, (int64_t)src_len);
    n00b_scanner_t      *scanner = n00b_scanner_new(buf, n00b_lang_tokenize, g);
    n00b_token_stream_t *ts      = n00b_token_stream_new(scanner);

    if (show_tokens) {
        printf("=== Tokens ===\n");
        dump_tokens(ts);
        printf("\n");
        n00b_stream_reset(ts);
    }

    // Parse.
    if (show_states) {
        // Direct Earley parse so we can dump states before freeing.
        printf("=== Earley Parse (with state dump) ===\n");

        n00b_earley_parser_t *earley = n00b_earley_new(g);
        bool ok = n00b_earley_parse(earley, ts);

        printf("\n=== Earley States ===\n");
        n00b_parser_print_states(earley, stdout, true);
        printf("\n");

        if (ok) {
            int32_t count = n00b_earley_parse_count(earley);
            printf("Parse OK — %d completion(s)\n\n", count);

            n00b_parse_forest_t forest = n00b_earley_get_forest(earley);
            int32_t tree_count = n00b_parse_forest_count(&forest);

            if (tree_count > 0) {
                printf("=== Parse Tree ===\n");
                n00b_tree_print(n00b_parse_forest_best(&forest), g, stdout);
                printf("\n");
            }

            n00b_parse_forest_free(&forest);
        }
        else {
            printf("Parse FAILED.\n");

            n00b_earley_diagnostics_t diag = {0};
            n00b_earley_extract_diagnostics(earley, &diag);
            fprintf(stderr, "Error at line %u, col %u",
                    diag.error_loc.line, diag.error_loc.column);

            if (diag.error_loc.got && diag.error_loc.got->data) {
                fprintf(stderr, ": got '%.*s'",
                        (int)diag.error_loc.got->u8_bytes,
                        diag.error_loc.got->data);
            }

            fprintf(stderr, "\n");

            if (diag.expected_count > 0) {
                fprintf(stderr, "Expected:");

                for (int32_t i = 0; i < diag.expected_count; i++) {
                    n00b_string_t *tname = n00b_get_terminal_name(
                        g, diag.expected_ids[i]);

                    if (tname && tname->data) {
                        fprintf(stderr, " %.*s",
                                (int)tname->u8_bytes, tname->data);
                    }
                    else {
                        fprintf(stderr, " tid=%lld",
                                (long long)diag.expected_ids[i]);
                    }
                }

                fprintf(stderr, "\n");
            }

            if (diag.expected_ids)  n00b_free(diag.expected_ids);
            if (diag.expected_desc) n00b_free(diag.expected_desc);
            if (diag.active_ctx)    n00b_free(diag.active_ctx);
        }

        n00b_earley_free(earley);
    }
    else {
        const char *mode_name = (mode == N00B_PARSE_MODE_EARLEY_ONLY) ? "earley"
                              : (mode == N00B_PARSE_MODE_PWZ_ONLY)    ? "pwz"
                                                                      : "default";

        if (!quiet) {
            printf("=== Parse (mode: %s) ===\n", mode_name);
        }

        n00b_parse_result_t *r = n00b_grammar_parse(g, ts);

        if (!n00b_parse_result_ok(r)) {
            n00b_string_t *err = n00b_parse_result_error_string(r);
            fprintf(stderr, "Parse failed: %.*s\n",
                    (int)err->u8_bytes, err->data);

            n00b_string_t *expected = n00b_parse_result_expected_string(r);

            if (expected->u8_bytes > 0) {
                fprintf(stderr, "Expected: %.*s\n",
                        (int)expected->u8_bytes, expected->data);
            }

            n00b_parse_result_free(r);
            /* src is GC-managed (read_file uses n00b_alloc_array). */
            return 1;
        }

        int32_t tree_count = n00b_parse_result_tree_count(r);

        if (!quiet) {
            printf("Parse OK — %d tree(s)%s\n\n",
                   tree_count,
                   n00b_parse_result_ambiguous(r) ? " [AMBIGUOUS]" : "");
        }

        // Print parse tree.
        n00b_parse_tree_t *tree = n00b_parse_result_tree(r);

        if (!quiet) {
            printf("=== Parse Tree ===\n");
            n00b_tree_print(tree, g, stdout);
            printf("\n");
        }

        // Diagnostic accumulator.
        n00b_diag_ctx_t *diag_ctx = n00b_diag_ctx_new();

        // Annotation walk.
        if (!quiet) {
            printf("=== Annotation Walk ===\n");
        }

        n00b_annot_result_t *ar = n00b_compile_walk(g, tree);

        if (!quiet) {
            if (ar && ar->symtab) {
                printf("Symtab populated.\n");
            }
            else {
                printf("(no annotations fired)\n");
            }
        }

        // Import type-check errors.
        if (run_typecheck && ar && ar->tc_ctx) {
            n00b_diag_import_tc_errors(diag_ctx, ar->tc_ctx);
        }

        // Symbol table.
        if (show_symtab) {
            printf("\n=== Symbol Table ===\n");
            dump_symtab(tree);
            printf("\n");
        }

        // CF labels.
        if (show_labels && ar && ar->cf_labels) {
            printf("\n=== CF Labels ===\n");
            n00b_cf_labels_print(ar->cf_labels, g, stdout);
            printf("\n");
        }

        // --run mode: codegen + JIT + execute.
        if (run_mode) {
            n00b_dict_untyped_t *embed_reg = n00b_embed_registry_new();
            n00b_ffi_embed_register(embed_reg);

            n00b_cg_session_t *session = n00b_cg_session_new(
                g, .type_map = n00b_type_map,
                   .embed_registry = embed_reg);

            n00b_load_builtins(g, session);

            bool    run_ok = false;
            int64_t result = n00b_cg_session_run_module(
                session, tree, .annot = ar, .ok = &run_ok);

            if (run_ok) {
                printf("=> %lld\n", (long long)result);
            }
            else {
                fprintf(stderr, "error: codegen/JIT failed\n");
            }

            n00b_cg_session_free(session);

            if (ar && ar->symtab) {
                n00b_symtab_free(ar->symtab);
            }

            n00b_diag_print_all(diag_ctx, src, source_file);
            n00b_diag_ctx_free(diag_ctx);
            n00b_parse_result_free(r);
            /* src is GC-managed (read_file uses n00b_alloc_array). */
            n00b_shutdown();

            return run_ok ? 0 : 1;
        }

        // CFG / CDG / DFG + Analysis.
        bool need_graphs = show_cfg || show_cdg || show_dfg || run_analyze;

        if (need_graphs && ar && ar->cf_labels) {
            n00b_cfg_t *cfg = n00b_build_cfg(ar->cf_labels, tree, r"module",
                                                ar->symtab);

            if (cfg) {
                if (show_cfg) {
                    printf("=== CFG ===\n");
                    n00b_cfg_print(cfg, g, stdout);
                    printf("\n");
                }

                n00b_cdg_t *cdg = NULL;

                if (show_cdg) {
                    cdg = n00b_build_cdg(cfg);

                    if (cdg) {
                        printf("=== CDG ===\n");
                        n00b_cdg_print(cdg, g, stdout);
                        printf("\n");
                    }
                    else {
                        printf("(CDG build returned NULL)\n");
                    }
                }

                n00b_dfg_t *dfg = NULL;

                if (show_dfg || run_analyze) {
                    dfg = n00b_build_dfg(cfg, ar->cf_labels, g, ar);

                    if (dfg && show_dfg) {
                        printf("=== DFG ===\n");
                        n00b_dfg_print(dfg, g, stdout);
                        printf("\n");
                    }
                    else if (!dfg) {
                        printf("(DFG build returned NULL)\n");
                    }
                }

                // Run analysis.
                if (run_analyze && dfg) {
                    n00b_analyze_ctx_t actx = {
                        .cfg       = cfg,
                        .cdg       = cdg,
                        .dfg       = dfg,
                        .symtab    = ar->symtab,
                        .cf_labels = ar->cf_labels,
                        .annot     = ar,
                        .grammar   = g,
                        .diag      = diag_ctx,
                        .func_name = r"module",
                    };

                    n00b_analyze_all(&actx);
                }

                if (dfg) {
                    n00b_dfg_free(dfg);
                }

                if (cdg) {
                    n00b_cdg_free(cdg);
                }

                n00b_cfg_free(cfg);
            }
            else if (!quiet) {
                printf("(CFG build returned NULL)\n");
            }
        }

        // Print all collected diagnostics.
        n00b_diag_print_all(diag_ctx, src, source_file);

        int exit_code = n00b_diag_has_errors(diag_ctx) ? 1 : 0;

        n00b_diag_ctx_free(diag_ctx);

        if (ar && ar->symtab) {
            n00b_symtab_free(ar->symtab);
        }

        n00b_parse_result_free(r);

        /* src is GC-managed (read_file uses n00b_alloc_array). */
        n00b_shutdown();

        return exit_code;
    }

    /* src is GC-managed. */

    n00b_shutdown();
    return 0;
}

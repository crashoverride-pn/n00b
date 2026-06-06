// n00b_repl.c — Interactive REPL for the n00b language.
//
// Statement-at-a-time REPL:
//   - Buffers input, parses from the 'module' production on each Enter
//   - Incomplete input (EOF while expecting more) → "..." continuation prompt
//   - Parse error at non-EOF token → report error
//   - Complete parse → walk top-level statements:
//       * func-def  → emit as top-level MIR function, compile, register
//       * other     → wrap in _eval, execute, print result
//
// Uses a persistent n00b_cg_session_t so functions defined in one input
// are callable from subsequent inputs.

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
#include "n00b/n00b_compile.h"
#include "n00b/n00b_tokenizer.h"
#include "n00b/n00b_module_loader.h"
#include "slay/codegen.h"
#include "slay/diagnostic.h"
#include "n00b/embed.h"
#include "n00b/embed_ffi.h"
#include "n00b/n00b_type_map.h"
#include "slay/grammar.h"
#include "slay/n00b_parse.h"
#include "slay/parse_tree.h"
#include "slay/token.h"
#include "vendor/linenoise.h"

// ============================================================================
// Builtins loading: auto-import lib/std/builtins.n into a codegen session.
// Shared between n00b and n00b_dev executables (both link this file).
// ============================================================================

bool
n00b_load_builtins(n00b_grammar_t *g, n00b_cg_session_t *session)
{
    FILE *f = NULL;

    const char *try_paths[] = {
        "lib/std/builtins.n",
        "../lib/std/builtins.n",
        "../../lib/std/builtins.n",
        NULL,
    };

    const char **p;
    for (p = try_paths; *p; p++) {
        f = fopen(*p, "r");

        if (f) {
            break;
        }
    }

    if (!f) {
        const char *srcroot = getenv("MESON_SOURCE_ROOT");

        if (srcroot) {
            char path[1024];
            snprintf(path, sizeof(path), "%s/lib/std/builtins.n", srcroot);
            f = fopen(path, "r");
        }
    }

    if (!f) {
        // Builtins not found — not fatal, just skip.
        return true;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *raw = n00b_alloc_array(char, (size_t)len + 1);
    fread(raw, 1, (size_t)len, f);
    raw[len] = '\0';
    fclose(f);

    n00b_buffer_t *buf = n00b_buffer_from_bytes(raw, (int64_t)len);

    // Tokenize.
    n00b_scanner_t      *scanner = n00b_scanner_new(buf, n00b_lang_tokenize, g);
    n00b_token_stream_t *ts      = n00b_token_stream_new(scanner);

    // Parse.
    n00b_parse_result_t *r = n00b_grammar_parse(g, ts);

    if (!n00b_parse_result_ok(r)) {
        n00b_string_t *err = n00b_parse_result_error_string(r);
        fprintf(stderr, "warning: builtins.n parse failed: %.*s\n",
                (int)err->u8_bytes, err->data);
        n00b_parse_result_free(r);
        return false;
    }

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);

    // Annotation walk.
    n00b_annot_result_t *ar = n00b_compile_walk(g, tree);

    // Run the builtins module on the session.
    // This triggers FFI embed handlers, registering wrapper functions.
    bool    ok     = false;
    n00b_cg_session_run_module(session, tree,
                                .annot      = ar,
                                .entry_name = "_builtins_init",
                                .ok         = &ok);

    n00b_parse_result_free(r);

    if (!ok) {
        fprintf(stderr, "warning: builtins.n codegen failed\n");
        return false;
    }

    return true;
}

// ============================================================================
// REPL state
// ============================================================================

typedef struct {
    n00b_grammar_t      *grammar;
    n00b_cg_session_t   *session;
    char                *input_buf;
    size_t               input_len;
    size_t               input_cap;
    int                  eval_count;
} n00b_repl_state_t;

// ============================================================================
// Parse-attempt result
// ============================================================================

typedef enum {
    REPL_PARSE_OK,
    REPL_PARSE_INCOMPLETE,
    REPL_PARSE_ERROR,
} repl_parse_status_t;

// ============================================================================
// Input buffer management
// ============================================================================

static void
repl_buf_reset(n00b_repl_state_t *state)
{
    state->input_len = 0;

    if (state->input_buf) {
        state->input_buf[0] = '\0';
    }
}

static void
repl_buf_append(n00b_repl_state_t *state, const char *line)
{
    size_t line_len = strlen(line);
    size_t need     = state->input_len + line_len + 2; // +newline +nul

    if (need > state->input_cap) {
        size_t new_cap = need * 2;

        if (new_cap < 1024) {
            new_cap = 1024;
        }

        // GC-managed grow: allocate, copy, drop the old reference.
        // The old buffer becomes unreachable and is collected. Avoids
        // raw realloc (n00b policy: no malloc/realloc/free outside
        // bootstrap).
        char *new_buf = n00b_alloc_array(char, new_cap);
        if (state->input_buf && state->input_len > 0) {
            memcpy(new_buf, state->input_buf, state->input_len);
        }
        state->input_buf = new_buf;
        state->input_cap = new_cap;
    }

    // Append newline between lines if we already have content.
    if (state->input_len > 0) {
        state->input_buf[state->input_len++] = '\n';
    }

    memcpy(state->input_buf + state->input_len, line, line_len);
    state->input_len += line_len;
    state->input_buf[state->input_len] = '\0';
}

// ============================================================================
// Parse attempt with incomplete detection
// ============================================================================

static repl_parse_status_t
try_parse(n00b_repl_state_t     *state,
          const char            *input,
          n00b_parse_result_t  **out)
{
    n00b_buffer_t       *buf = n00b_buffer_from_bytes((char *)input,
                                                       (int64_t)strlen(input));
    n00b_scanner_t      *s   = n00b_scanner_new(buf, n00b_lang_tokenize,
                                                  state->grammar);
    n00b_token_stream_t *ts  = n00b_token_stream_new(s);

    n00b_parse_result_t *r = n00b_grammar_parse(state->grammar, ts);

    if (n00b_parse_result_ok(r)) {
        *out = r;
        return REPL_PARSE_OK;
    }

    // Check if incomplete: parser hit EOF but expected more tokens.
    n00b_error_location_t loc = n00b_parse_result_error_location(r);

    if (loc.got_id == N00B_TOK_EOF) {
        n00b_parse_result_free(r);
        *out = NULL;
        return REPL_PARSE_INCOMPLETE;
    }

    // Real syntax error at a non-EOF token.
    *out = r;
    return REPL_PARSE_ERROR;
}

// ============================================================================
// Check if a parse tree node is (or contains) a func-def
// ============================================================================

static bool
is_func_def_node(n00b_parse_tree_t *node)
{
    return n00b_pt_is_nt(node, "func-def");
}

// DFS through groups and single-child wrapper NTs to find a func-def.
static bool
contains_func_def(n00b_parse_tree_t *node)
{
    if (!node || n00b_pt_is_token(node)) {
        return false;
    }

    if (is_func_def_node(node)) {
        return true;
    }

    // Recurse through group nodes (from BNF quantifiers).
    if (n00b_pt_is_group(node)) {
        size_t nc = n00b_pt_num_children(node);

        for (size_t i = 0; i < nc; i++) {
            if (contains_func_def(n00b_pt_get_child(node, i))) {
                return true;
            }
        }

        return false;
    }

    // For regular NTs with exactly one child, look through
    // (e.g., top-level-stmt → func-def).
    size_t nc = n00b_pt_num_children(node);

    if (nc == 1) {
        return contains_func_def(n00b_pt_get_child(node, 0));
    }

    return false;
}

// ============================================================================
// Collect top-level statements from a module parse tree
// ============================================================================

static int
collect_top_level_stmts(n00b_parse_tree_t  *tree,
                        n00b_parse_tree_t **out,
                        int                 max)
{
    // The module parse tree has top-level statements as children,
    // possibly wrapped in group nodes from the grammar's quantifiers.
    // DFS through groups to collect all non-group, non-token children.
    int count = 0;

    n00b_parse_tree_t *stack[256];
    int                sp = 0;

    // Push direct children of the module root.
    size_t nc = n00b_pt_num_children(tree);

    for (size_t i = 0; i < nc && sp < 256; i++) {
        stack[sp++] = n00b_pt_get_child(tree, i);
    }

    while (sp > 0 && count < max) {
        n00b_parse_tree_t *cur = stack[--sp];

        if (!cur || n00b_pt_is_token(cur)) {
            continue;
        }

        if (n00b_pt_is_group(cur)) {
            // Expand group: push children in reverse for L-to-R order.
            size_t gnc = n00b_pt_num_children(cur);

            for (size_t i = gnc; i > 0; i--) {
                if (sp < 256) {
                    stack[sp++] = n00b_pt_get_child(cur, i - 1);
                }
            }

            continue;
        }

        // Real top-level statement node.
        out[count++] = cur;
    }

    return count;
}

// ============================================================================
// Emit function definitions from a module parse tree
// ============================================================================

static bool
emit_func_defs(n00b_repl_state_t   *state,
               n00b_parse_tree_t   *tree,
               n00b_annot_result_t *annot)
{
    // Create a module for the function definitions.
    char mod_name[64];
    snprintf(mod_name, sizeof(mod_name), "repl_def_%d", state->eval_count);

    n00b_cg_module_t *m = n00b_cg_module_new(state->session, mod_name);

    if (annot) {
        n00b_cg_module_set_annot(m, annot);
    }

    // DFS through the tree to find and emit all func-def nodes.
    n00b_parse_tree_t *stack[256];
    int                sp    = 0;
    int                count = 0;

    stack[sp++] = tree;

    while (sp > 0) {
        n00b_parse_tree_t *cur = stack[--sp];

        if (!cur || n00b_pt_is_token(cur)) {
            continue;
        }

        if (is_func_def_node(cur)) {
            // codegen_walk emits as top-level MIR function (cur_func == NULL).
            n00b_codegen_lower(state->session, cur);
            count++;
            continue;
        }

        // Push children in reverse for L-to-R order.
        size_t nc = n00b_pt_num_children(cur);

        for (size_t i = nc; i > 0; i--) {
            if (sp < 256) {
                stack[sp++] = n00b_pt_get_child(cur, i - 1);
            }
        }
    }

    if (count == 0) {
        // No func-defs found — shouldn't happen but handle gracefully.
        return true;
    }

    // Compile the module so the functions are JIT'd and callable.
    void *fn = n00b_cg_module_compile(m, NULL);
    (void)fn;

    // Merge symbols so subsequent expressions can call these functions.
    n00b_cg_session_merge_module(state->session, m);

    return true;
}

// ============================================================================
// Evaluate an expression/statement and print the result
// ============================================================================

static void
eval_and_print(n00b_repl_state_t   *state,
               n00b_parse_tree_t   *tree,
               n00b_annot_result_t *annot)
{
    bool               ok       = false;
    n00b_cg_type_tag_t ret_type = N00B_CG_VOID;
    int64_t            val      = n00b_cg_session_eval_tree(
        state->session, tree,
        .annot = annot, .ok = &ok, .out_type = &ret_type);

    if (!ok) {
        fprintf(stderr, "error: codegen/JIT failed\n");
        return;
    }

    switch (ret_type) {
    case N00B_CG_VOID:
        // Void-producing statement (print, assign, etc.) — no output.
        break;

    case N00B_CG_BOOL:
        printf("=> %s\n", val ? "true" : "false");
        break;

    case N00B_CG_STRING: {
        n00b_string_t *s = (n00b_string_t *)(uintptr_t)val;

        if (s && s->data) {
            printf("=> \"%.*s\"\n", (int)s->u8_bytes, s->data);
        }
        else {
            printf("=> nil\n");
        }

        break;
    }

    case N00B_CG_NIL:
        printf("=> nil\n");
        break;

    case N00B_CG_F32:
    case N00B_CG_F64: {
        double d;
        memcpy(&d, &val, sizeof(d));
        printf("=> %g\n", d);
        break;
    }

    default:
        // All integer types.
        printf("=> %lld\n", (long long)val);
        break;
    }
}

// ============================================================================
// Process a successfully parsed module tree
//
// Walks top-level statements and routes each one:
//   func-def  → emit as top-level MIR function (no output)
//   other     → wrap in _eval, execute, print result
// ============================================================================

static void
process_parsed_input(n00b_repl_state_t   *state,
                     n00b_parse_tree_t   *tree,
                     n00b_annot_result_t *annot)
{
    // Collect top-level statements.
    n00b_parse_tree_t *stmts[256];
    int n_stmts = collect_top_level_stmts(tree, stmts, 256);

    // Check if there are any func-defs.
    bool has_func_defs = false;
    bool has_exprs     = false;

    for (int i = 0; i < n_stmts; i++) {
        if (contains_func_def(stmts[i])) {
            has_func_defs = true;
        } else {
            has_exprs = true;
        }
    }

    // If there are func-defs, emit them all as top-level MIR functions.
    if (has_func_defs) {
        emit_func_defs(state, tree, annot);
    }

    // If there are non-func-def statements, evaluate them.
    // When func-defs and expressions are mixed, use run_module which
    // handles both (func-defs already emitted get skipped in pass 2).
    if (has_exprs) {
        if (has_func_defs) {
            // Mixed: use run_module on the full tree.
            // func-defs were already emitted above, so run_module's
            // pass 1 will re-emit them (harmless — they get the same
            // names and MIR handles duplicates). Pass 2 wraps the rest.
            //
            // Actually, to avoid double-emission, just eval the
            // full tree which will skip func-defs (cur_func != NULL).
            eval_and_print(state, tree, annot);
        } else {
            // Pure expressions: eval the whole tree directly.
            eval_and_print(state, tree, annot);
        }
    } else if (has_func_defs) {
        // Only func-defs — no output, just confirmation.
        // (Python-like: defining a function produces no output.)
    }

    state->eval_count++;
}

// ============================================================================
// REPL commands
// ============================================================================

static bool
dispatch_command(const char *line)
{
    // Skip leading whitespace after ':'.
    while (*line == ' ' || *line == '\t') {
        line++;
    }

    if (strcmp(line, "quit") == 0 || strcmp(line, "q") == 0) {
        return true; // Signal exit.
    }

    if (strcmp(line, "clear") == 0 || strcmp(line, "c") == 0) {
        linenoiseClearScreen();
        return false;
    }

    if (strcmp(line, "help") == 0 || strcmp(line, "h") == 0) {
        printf("n00b REPL commands:\n");
        printf("  :quit, :q     Exit the REPL\n");
        printf("  :clear, :c    Clear the screen\n");
        printf("  :help, :h     Show this help\n");
        printf("\n");
        printf("Enter n00b expressions to evaluate them.\n");
        printf("Multi-line input: incomplete expressions auto-continue.\n");
        printf("Press Ctrl-D to exit.\n");
        return false;
    }

    fprintf(stderr, "Unknown command: :%s\n", line);
    fprintf(stderr, "Type :help for available commands.\n");
    return false;
}

// ============================================================================
// Main REPL loop
// ============================================================================

int
n00b_repl_run(n00b_grammar_t *grammar)
{
    n00b_dict_untyped_t *repl_embed_reg = n00b_embed_registry_new();
    n00b_ffi_embed_register(repl_embed_reg);

    n00b_cg_session_t *repl_session = n00b_cg_session_new(grammar,
                                         .type_map = n00b_type_map,
                                         .embed_registry = repl_embed_reg);

    // Load builtins (print, etc.) before REPL interaction.
    n00b_load_builtins(grammar, repl_session);

    n00b_repl_state_t state = {
        .grammar        = grammar,
        .session        = repl_session,
        .input_buf      = NULL,
        .input_len      = 0,
        .input_cap      = 0,
        .eval_count     = 0,
    };

    linenoiseSetMultiLine(1);
    linenoiseHistorySetMaxLen(100);

    printf("n00b REPL (type :help for commands, Ctrl-D to exit)\n");

    const char *prompt = "n00b> ";

    while (true) {
        char *line = linenoise(prompt);

        if (!line) {
            // Ctrl-D or EOF.
            printf("\n");
            break;
        }

        // Skip empty lines when not in continuation.
        if (line[0] == '\0' && state.input_len == 0) {
            linenoiseFree(line);
            continue;
        }

        // REPL commands (only at top level, not in continuation).
        if (line[0] == ':' && state.input_len == 0) {
            bool should_quit = dispatch_command(line + 1);
            linenoiseFree(line);

            if (should_quit) {
                break;
            }

            continue;
        }

        // Append to input buffer.
        repl_buf_append(&state, line);
        linenoiseFree(line);

        // Try to parse the accumulated input as a complete module.
        n00b_parse_result_t *parse_result = NULL;
        repl_parse_status_t  status = try_parse(&state, state.input_buf,
                                                 &parse_result);

        switch (status) {
        case REPL_PARSE_INCOMPLETE:
            // Need more input — show continuation prompt.
            prompt = "  ... ";
            continue;

        case REPL_PARSE_ERROR: {
            // Print error.
            n00b_string_t *err = n00b_parse_result_error_string(parse_result);
            fprintf(stderr, "Parse error: %.*s\n",
                    (int)err->u8_bytes, err->data);

            n00b_string_t *expected = n00b_parse_result_expected_string(
                parse_result);

            if (expected->u8_bytes > 0) {
                fprintf(stderr, "Expected: %.*s\n",
                        (int)expected->u8_bytes, expected->data);
            }

            n00b_parse_result_free(parse_result);
            repl_buf_reset(&state);
            prompt = "n00b> ";
            continue;
        }

        case REPL_PARSE_OK:
            break;
        }

        // Add to history.
        linenoiseHistoryAdd(state.input_buf);

        // Get parse tree.
        n00b_parse_tree_t *tree = n00b_parse_result_tree(parse_result);

        // Annotation walk.
        n00b_annot_result_t *annot = n00b_compile_walk(grammar, tree);

        if (!annot) {
            fprintf(stderr, "error: annotation walk failed\n");
            n00b_parse_result_free(parse_result);
            repl_buf_reset(&state);
            prompt = "n00b> ";
            continue;
        }

        // Resolve use statements (load imported modules).
        if (!n00b_resolve_use_stmts(state.session, grammar, tree, annot, NULL)) {
            n00b_parse_result_free(parse_result);
            repl_buf_reset(&state);
            prompt = "n00b> ";
            continue;
        }

        // Process the parsed input: route func-defs vs expressions.
        process_parsed_input(&state, tree, annot);

        // Cleanup.
        if (annot->symtab) {
            n00b_symtab_free(annot->symtab);
        }

        n00b_parse_result_free(parse_result);
        repl_buf_reset(&state);
        prompt = "n00b> ";
    }

    n00b_cg_session_free(state.session);
    // state.input_buf is GC-managed (see grow path above); no free.

    return 0;
}

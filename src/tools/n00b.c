// n00b.c — Main n00b CLI entry point.
//
// Provides compile, run, and repl subcommands via the commander module.
// Default mode (no subcommand) is repl.
//
// The "run" and default paths load the n00b grammar, parse each source
// file, run the annotation walk, codegen via MIR, JIT-compile, and
// execute the first file's _main.
//
// Debug/inspection flags (--debug-tokens, --debug-grammar, etc.) add
// diagnostic output on top of normal execution.

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <process.h>
#include <sys/stat.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif

#ifdef _WIN32
#ifndef S_ISDIR
#define S_ISDIR(mode) (((mode) & S_IFMT) == S_IFDIR)
#endif
#define close _close
#define fdopen _fdopen
#define getpid _getpid
#define mkdir(path, mode) _mkdir(path)
#define open _open
#define unlink _unlink
#endif

#include "n00b.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "core/string.h"
#include "conduit/print.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "slay/annot_walk.h"
#include "slay/codegen.h"
#include "n00b/n00b_compile_binary.h"
#include "n00b/embed.h"
#include "n00b/embed_ffi.h"
#include "n00b/n00b_compile.h"
#include "n00b/n00b_module_loader.h"
#include "n00b/n00b_type_map.h"
#include "slay/bnf.h"
#include "slay/cf_label.h"
#include "slay/cdg.h"
#include "slay/cfg.h"
#include "slay/commander.h"
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
#include "util/errno_str.h"
#include "typecheck/types.h"
#include "typecheck/print.h"
#ifdef _WIN32
#include "internal/win32_sockets.h"
#ifndef ELOOP
#define ELOOP 40
#endif
#endif

// From n00b_repl.c.
extern int n00b_repl_run(n00b_grammar_t *grammar);

// ============================================================================
// Debug options
// ============================================================================

typedef struct {
    bool              show_tokens;
    bool              show_grammar;
    bool              show_states;
    bool              show_lr0;
    bool              show_cfg;
    bool              show_cdg;
    bool              show_dfg;
    bool              show_labels;
    bool              show_symtab;
    bool              run_analyze;
    bool              run_typecheck;
    bool              quiet;
    n00b_parse_mode_t parse_mode;
} debug_opts_t;

static bool compile_resolve_source_imports(n00b_cg_session_t   *session,
                                           n00b_grammar_t      *g,
                                           n00b_string_t       *source_file,
                                           n00b_parse_tree_t   *tree,
                                           n00b_annot_result_t *annot);

// ============================================================================
// Compile helpers
// ============================================================================

static const char *
compile_compiler(void)
{
    const char *env = getenv("N00B_COMPILER");

    if (env && *env) {
        return env;
    }

    return "clang";
}

static unsigned long
compile_process_id(void)
{
#ifdef _WIN32
    return (unsigned long)_getpid();
#else
    return (unsigned long)getpid();
#endif
}

static bool
compile_temp_path(char *buf, size_t buf_len, const char *stem, int index, const char *suffix)
{
    const char *dir = getenv("TMPDIR");

#ifdef _WIN32
    if (!dir || !*dir) {
        dir = getenv("TEMP");
    }
    if (!dir || !*dir) {
        dir = getenv("TMP");
    }
#endif
    if (!dir || !*dir) {
#ifdef _WIN32
        dir = ".";
#else
        dir = "/tmp";
#endif
    }

    size_t      dir_len = strlen(dir);
    const char *sep     = "";

    if (dir_len > 0) {
        char last = dir[dir_len - 1];

        if (last != '/' && last != '\\') {
            sep = "/";
        }
    }

    int n = snprintf(buf,
                     buf_len,
                     "%s%sn00b_%s_%lu_%d%s",
                     dir,
                     sep,
                     stem,
                     compile_process_id(),
                     index,
                     suffix);

    return n > 0 && (size_t)n < buf_len;
}

static int
compile_spawn_wait(const char **argv)
{
    const char *program = argv[0];

#ifdef _WIN32
    int argc = 0;

    while (argv[argc]) {
        argc++;
    }

    // Pre-n00b_init: allocate the spawn argv + quoted args from a private,
    // non-GC arena (the n00b allocator works pre-GC-heap via a private arena)
    // instead of libc malloc.  Bulk-freed with n00b_allocator_destroy after the
    // spawn; error paths just return (process exits, OS reclaims).
    n00b_arena_t *spawn_arena = n00b_new_arena(.use_gc = false,
                                               .name   = "win-spawn-argv");
    const char  **spawn_argv  = n00b_alloc_array(const char *,
                                                (size_t)argc + 1,
                                                .allocator = (n00b_allocator_t *)spawn_arena);

    if (!spawn_argv) {
        fprintf(stderr, "error: cannot allocate compiler argument list\n");
        return 1;
    }

    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i];
        bool        q   = false;

        if (!arg || !*arg) {
            q = true;
        }
        else {
            const char *p;
            for (p = arg; *p; p++) {
                if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '"') {
                    q = true;
                    break;
                }
            }
        }

        if (!q) {
            size_t len = strlen(arg);
            char  *dup = n00b_alloc_array(char, len + 1,
                                          .allocator = (n00b_allocator_t *)spawn_arena);

            if (!dup) {
                fprintf(stderr, "error: cannot allocate compiler argument\n");
                n00b_allocator_destroy((n00b_allocator_t *)spawn_arena);
                return 1;
            }

            memcpy(dup, arg, len + 1);
            spawn_argv[i] = dup;
            continue;
        }

        size_t len = arg ? strlen(arg) : 0;
        char  *out = n00b_alloc_array(char, len * 2 + 3,
                                      .allocator = (n00b_allocator_t *)spawn_arena);

        if (!out) {
            fprintf(stderr, "error: cannot allocate compiler argument\n");
            n00b_allocator_destroy((n00b_allocator_t *)spawn_arena);
            return 1;
        }

        char  *dst         = out;
        size_t backslashes = 0;

        *dst++ = '"';

        for (size_t j = 0; j < len; j++) {
            char ch = arg[j];

            if (ch == '\\') {
                backslashes++;
                continue;
            }

            if (ch == '"') {
                while (backslashes--) {
                    *dst++ = '\\';
                    *dst++ = '\\';
                }
                *dst++      = '\\';
                *dst++      = '"';
                backslashes = 0;
                continue;
            }

            while (backslashes--) {
                *dst++ = '\\';
            }
            backslashes = 0;
            *dst++      = ch;
        }

        while (backslashes--) {
            *dst++ = '\\';
            *dst++ = '\\';
        }

        *dst++ = '"';
        *dst   = '\0';

        spawn_argv[i] = out;
    }

    spawn_argv[argc] = NULL;

    intptr_t rc = _spawnvp(_P_WAIT, program, spawn_argv);

    n00b_allocator_destroy((n00b_allocator_t *)spawn_arena);

    if (rc == -1) {
        n00b_eprintf("error: spawn(«#») failed: «#»",
                     n00b_string_from_cstr(program),
                     n00b_errno_str(errno));
        return 127;
    }

    return (int)rc;
#else
    pid_t pid = fork();

    if (pid < 0) {
        n00b_eprintf("error: fork() failed: «#»", n00b_errno_str(errno));
        return 1;
    }

    if (pid == 0) {
        execvp(program, (char *const *)argv);
        n00b_eprintf("error: execvp(«#») failed: «#»",
                     n00b_string_from_cstr(program),
                     n00b_errno_str(errno));
        _exit(127);
    }

    int status;

    if (waitpid(pid, &status, 0) < 0) {
        n00b_eprintf("error: waitpid() failed: «#»", n00b_errno_str(errno));
        return 1;
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }

    return 1;
#endif
}

// ============================================================================
// Token dumping (ported from n00b_dev.c)
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
            text               = val->data;
            tlen               = val->u8_bytes;
        }

        printf("%4d  tid=%-20lld L%u:C%u  \"%.*s\"\n",
               index++,
               (long long)tok->tid,
               tok->line,
               tok->column,
               (int)tlen,
               text);
    }
}

// ============================================================================
// Symbol table dumping (ported from n00b_dev.c)
// ============================================================================

static const char *
sym_kind_str(n00b_sym_kind_t kind)
{
    switch (kind) {
    case N00B_SYM_VARIABLE:
        return "var";
    case N00B_SYM_FUNCTION:
        return "func";
    case N00B_SYM_TYPEDEF:
        return "type";
    case N00B_SYM_TAG:
        return "tag";
    case N00B_SYM_ENUM_CONST:
        return "enum";
    case N00B_SYM_LABEL:
        return "label";
    case N00B_SYM_PARAM:
        return "param";
    default:
        return "?";
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
        n00b_scope_t *scope  = pn->scope;
        int           indent = scope->depth;

        for (int i = 0; i < indent; i++) {
            printf("  ");
        }

        if (scope->name && scope->name->data && scope->name->u8_bytes > 0) {
            printf("scope \"%.*s\" (depth %d):\n",
                   (int)scope->name->u8_bytes,
                   scope->name->data,
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
                       (int)entry->name->u8_bytes,
                       entry->name->data,
                       (int)ts->u8_bytes,
                       ts->data,
                       line);
            }
            else {
                printf("%-6s %.*s  line %u",
                       sym_kind_str(entry->kind),
                       (int)entry->name->u8_bytes,
                       entry->name->data,
                       line);
            }

            if (entry->exposed_scope) {
                n00b_scope_t *es = entry->exposed_scope;

                if (es->name && es->name->data && es->name->u8_bytes > 0) {
                    printf("  [exposes \"%.*s\"]", (int)es->name->u8_bytes, es->name->data);
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
// Source file reading
// ============================================================================

static n00b_buffer_t *
read_source_file(n00b_string_t *path)
{
    FILE *f = fopen(path->data, "r");

    if (!f) {
        n00b_eprintf("error: cannot open '«#»'", path);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *raw = n00b_alloc_array(char, (size_t)len + 1);
    fread(raw, 1, (size_t)len, f);
    raw[len] = '\0';
    fclose(f);

    n00b_buffer_t *buf = n00b_buffer_from_bytes(raw, (int64_t)len);

    return buf;
}

// Runs during compilation (post-n00b_init), so the default n00b allocator is
// up — return an n00b_string_t (GC-managed) instead of a libc-malloc'd char*.
static n00b_string_t *
source_dirname_dup(n00b_string_t *path)
{
    if (!path || !path->data || path->u8_bytes <= 0) {
        return r".";
    }

    const char *data  = path->data;
    const char *slash = strrchr(data, '/');

    if (!slash) {
        return r".";
    }

    if (slash == data) {
        return r"/";
    }

    size_t len = (size_t)(slash - data);
    return n00b_string_from_raw(data, (int64_t)len);
}

// ============================================================================
// Grammar loading
// ============================================================================

static n00b_grammar_t *
load_n00b_grammar(n00b_string_t *grammar_file, n00b_parse_mode_t parse_mode)
{
    FILE *f = NULL;

    if (grammar_file && grammar_file->u8_bytes > 0) {
        f = fopen(grammar_file->data, "r");

        if (!f) {
            n00b_eprintf("error: cannot open grammar file '«#»'", grammar_file);
            return NULL;
        }
    }
    else {
        // Try relative paths from typical working directories.
        n00b_string_t *try_paths[] = {
            r"grammars/n00b.bnf",
            r"../grammars/n00b.bnf",
            r"../../grammars/n00b.bnf",
            NULL,
        };

        n00b_string_t **p;
        for (p = try_paths; *p; p++) {
            f = fopen((*p)->data, "r");

            if (f) {
                break;
            }
        }

        if (!f) {
            // Try MESON_SOURCE_ROOT.
            const char *srcroot = getenv("MESON_SOURCE_ROOT");

            if (srcroot) {
                char path[1024];
                snprintf(path, sizeof(path), "%s/grammars/n00b.bnf", srcroot);
                f = fopen(path, "r");
            }
        }

        if (!f) {
            n00b_eprintf("error: cannot find grammars/n00b.bnf");
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

    // Backend selection is fixed at instantiation; the `n00b` debug tool
    // chooses it from --pwz/--earley flags (parse_mode), error recovery off.
    n00b_grammar_t *g = n00b_grammar_new(.parse_mode     = parse_mode,
                                         .error_recovery = false);

    bool ok = n00b_bnf_load(bnf_text, r"module", g);

    if (!ok) {
        n00b_eprintf("error: n00b_bnf_load failed");
        n00b_grammar_free(g);
        return NULL;
    }

    return g;
}

// ============================================================================
// Version
// ============================================================================

static void
print_version(void)
{
    n00b_printf("n00b «#».«#».«#»",
                (int64_t)N00B_VERS_MAJOR,
                (int64_t)N00B_VERS_MINOR,
                (int64_t)N00B_VERS_PATCH);
}

// ============================================================================
// Usage text
// ============================================================================

static void
print_usage(void)
{
    n00b_eprintf(
        "Usage: n00b [command] [options] [files...]\n"
        "\n"
        "Commands:\n"
        "  compile   Compile n00b source files\n"
        "  run       Run n00b source files\n"
        "  repl      Interactive REPL (default)\n"
        "  help      Show this help message\n"
        "\n"
        "Options:\n"
        "  -h, --help              Show this help message\n"
        "  -V, --version           Show version information\n"
        "  -v, --verbose           Enable verbose output\n"
        "  -q, --quiet             Suppress non-essential output\n"
        "\n"
        "Debug flags:\n"
        "  --debug-tokens          Dump token stream\n"
        "  --debug-grammar         Print grammar\n"
        "  --debug-states          Dump Earley parse states\n"
        "  --debug-lr0             Print LR(0) table\n"
        "  --debug-cfg             Show control flow graph\n"
        "  --debug-cdg             Show control dependence graph\n"
        "  --debug-dfg             Show data flow graph\n"
        "  --debug-labels          Show CF labels\n"
        "  -s, --debug-symtab      Dump symbol table\n"
        "  -a, --debug-analyze     Run analysis pass\n"
        "  -t, --debug-typecheck   Run type checking\n"
        "  --debug-all             Enable all debug outputs\n"
        "  --debug-earley          Force Earley parser\n"
        "  --debug-pwz             Force PWZ parser\n"
        "  --debug-grammar-file    Custom grammar file path");
}

// ============================================================================
// Commander setup
// ============================================================================

static n00b_cmdr_t *
build_commander(void)
{
    n00b_cmdr_t *c = n00b_cmdr_new();

    n00b_cmdr_set_name(c, r"n00b");

    // Root-level flags.
    n00b_cmdr_add_flag(c,
                       n00b_string_empty(),
                       r"--help",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"Show help message");
    n00b_cmdr_add_flag_alias(c, n00b_string_empty(), r"--help", r"-h");

    n00b_cmdr_add_flag(c,
                       n00b_string_empty(),
                       r"--version",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"Show version");
    n00b_cmdr_add_flag_alias(c, n00b_string_empty(), r"--version", r"-V");

    n00b_cmdr_add_flag(c,
                       n00b_string_empty(),
                       r"--verbose",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"Verbose output");
    n00b_cmdr_add_flag_alias(c, n00b_string_empty(), r"--verbose", r"-v");

    // Debug flags.
    n00b_cmdr_add_flag(c,
                       n00b_string_empty(),
                       r"--debug-tokens",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"Dump token stream");
    n00b_cmdr_add_flag(c,
                       n00b_string_empty(),
                       r"--debug-grammar",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"Print grammar");
    n00b_cmdr_add_flag(c,
                       n00b_string_empty(),
                       r"--debug-states",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"Dump Earley parse states");
    n00b_cmdr_add_flag(c,
                       n00b_string_empty(),
                       r"--debug-lr0",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"Print LR(0) table");
    n00b_cmdr_add_flag(c,
                       n00b_string_empty(),
                       r"--debug-cfg",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"Show control flow graph");
    n00b_cmdr_add_flag(c,
                       n00b_string_empty(),
                       r"--debug-cdg",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"Show control dependence graph");
    n00b_cmdr_add_flag(c,
                       n00b_string_empty(),
                       r"--debug-dfg",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"Show data flow graph");
    n00b_cmdr_add_flag(c,
                       n00b_string_empty(),
                       r"--debug-labels",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"Show CF labels");
    n00b_cmdr_add_flag(c,
                       n00b_string_empty(),
                       r"--debug-symtab",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"Dump symbol table");
    n00b_cmdr_add_flag_alias(c, n00b_string_empty(), r"--debug-symtab", r"-s");
    n00b_cmdr_add_flag(c,
                       n00b_string_empty(),
                       r"--debug-analyze",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"Run analysis pass");
    n00b_cmdr_add_flag_alias(c, n00b_string_empty(), r"--debug-analyze", r"-a");
    n00b_cmdr_add_flag(c,
                       n00b_string_empty(),
                       r"--debug-typecheck",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"Run type checking");
    n00b_cmdr_add_flag_alias(c, n00b_string_empty(), r"--debug-typecheck", r"-t");
    n00b_cmdr_add_flag(c,
                       n00b_string_empty(),
                       r"--debug-all",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"Enable all debug outputs");
    n00b_cmdr_add_flag(c,
                       n00b_string_empty(),
                       r"--debug-earley",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"Force Earley parser");
    n00b_cmdr_add_flag(c,
                       n00b_string_empty(),
                       r"--debug-pwz",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"Force PWZ parser");
    n00b_cmdr_add_flag(c,
                       n00b_string_empty(),
                       r"--debug-grammar-file",
                       N00B_CMDR_TYPE_WORD,
                       true,
                       r"Custom grammar file path");
    n00b_cmdr_add_flag(c,
                       n00b_string_empty(),
                       r"--quiet",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"Suppress non-essential output");
    n00b_cmdr_add_flag_alias(c, n00b_string_empty(), r"--quiet", r"-q");

    // Root positional args (for bare `n00b foo.n` → repl with file).
    n00b_cmdr_add_positional(c, n00b_string_empty(), r"file", N00B_CMDR_TYPE_WORD, 0, -1);

    // compile subcommand.
    n00b_cmdr_add_command(c, r"compile", r"Compile n00b source files");
    n00b_cmdr_add_positional(c, r"compile", r"file", N00B_CMDR_TYPE_WORD, 1, -1);
    n00b_cmdr_add_flag(c,
                       r"compile",
                       r"--output",
                       N00B_CMDR_TYPE_WORD,
                       true,
                       r"Output binary path");
    n00b_cmdr_add_flag_alias(c, r"compile", r"--output", r"-o");
    n00b_cmdr_add_flag(c,
                       r"compile",
                       r"--lib-dir",
                       N00B_CMDR_TYPE_WORD,
                       true,
                       r"libn00b.a directory");
    n00b_cmdr_add_flag(c,
                       r"compile",
                       r"--keep-objects",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"Keep .o files");
    n00b_cmdr_add_flag(c,
                       r"compile",
                       r"--cache-dir",
                       N00B_CMDR_TYPE_WORD,
                       true,
                       r"Directory for compile cache artifacts");
    n00b_cmdr_add_flag(c,
                       r"compile",
                       r"--cache-only",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"Store or restore compile cache metadata without linking");

    // run subcommand.
    n00b_cmdr_add_command(c, r"run", r"Run n00b source files");
    n00b_cmdr_add_positional(c, r"run", r"file", N00B_CMDR_TYPE_WORD, 1, -1);

    // repl subcommand.
    n00b_cmdr_add_command(c, r"repl", r"Interactive REPL");
    n00b_cmdr_add_positional(c, r"repl", r"file", N00B_CMDR_TYPE_WORD, 0, -1);

    // help subcommand.
    n00b_cmdr_add_command(c, r"help", r"Show detailed help");

    return c;
}

// Defined in n00b_repl.c (shared between n00b and n00b_dev executables).
extern bool n00b_load_builtins(n00b_grammar_t *g, n00b_cg_session_t *session);

// ============================================================================
// Run mode: parse → annotate → codegen → JIT → execute
// ============================================================================

// Walk a parse tree and emit diagnostics for error recovery nodes.
// Returns the number of error nodes found.
static int
collect_parse_errors(n00b_diag_ctx_t *diag, n00b_grammar_t *g, n00b_parse_tree_t *node)
{
    if (!node || n00b_tree_is_leaf(node)) {
        return 0;
    }

    int             count = 0;
    n00b_nt_node_t *pn    = &n00b_tree_node_value(node);

    if (pn->penalty > 0 && (pn->missing || pn->bad_prefix)) {
        n00b_diag_span_t span = n00b_diag_span_from_node(node);
        char             msg[256];

        if (pn->missing) {
            // The node's name tells us what was expected.
            const char *nt_name = pn->name ? pn->name->data : "token";
            snprintf(msg, sizeof(msg), "missing expected '%s'", nt_name);
            n00b_diag_push(diag,
                           N00B_DIAG_ERROR,
                           N00B_STAGE_PARSE,
                           r"P002",
                           n00b_string_from_cstr(msg),
                           span);
        }
        else if (pn->bad_prefix) {
            n00b_parse_tree_t *tok = n00b_pt_first_token(node);
            const char        *got = tok ? n00b_pt_token_text(tok) : NULL;

            if (got) {
                snprintf(msg,
                         sizeof(msg),
                         "unexpected '%s' before '%s'",
                         got,
                         pn->name ? pn->name->data : "here");
            }
            else {
                snprintf(msg,
                         sizeof(msg),
                         "unexpected token before '%s'",
                         pn->name ? pn->name->data : "here");
            }

            n00b_diag_push(diag,
                           N00B_DIAG_ERROR,
                           N00B_STAGE_PARSE,
                           r"P003",
                           n00b_string_from_cstr(msg),
                           span);
        }

        count++;
    }

    size_t nc = n00b_tree_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        count += collect_parse_errors(diag, g, n00b_tree_child(node, i));
    }

    return count;
}

static int
run_file(n00b_grammar_t *g, n00b_string_t *source_file, bool verbose, debug_opts_t *dbg)
{
    n00b_buffer_t *buf = read_source_file(source_file);

    if (!buf) {
        return 1;
    }

    // Create diagnostic accumulator early — all stages feed into this.
    n00b_diag_ctx_t *diag_ctx = n00b_diag_ctx_new();

    // Pre-parse debug output.
    if (dbg->show_grammar) {
        printf("=== Grammar ===\n");
        n00b_grammar_print(g, stdout);
        printf("\n");
    }

    if (dbg->show_lr0) {
        printf("=== LR(0) Table ===\n");
        n00b_lr0_print(g, stdout);
        printf("\n");
    }

    // Tokenize.
    n00b_scanner_t      *scanner = n00b_scanner_new(buf, n00b_lang_tokenize, g);
    n00b_token_stream_t *ts      = n00b_token_stream_new(scanner);

    if (dbg->show_tokens) {
        printf("=== Tokens ===\n");
        dump_tokens(ts);
        printf("\n");
        n00b_stream_reset(ts);
    }

    // Parse.
    n00b_parse_tree_t   *tree = NULL;
    n00b_parse_result_t *r    = NULL;

    if (dbg->show_states) {
        // Direct Earley parse so we can dump states.
        printf("=== Earley Parse (with state dump) ===\n");

        n00b_earley_parser_t *earley = n00b_earley_new(g);
        bool                  ok     = n00b_earley_parse(earley, ts);

        printf("\n=== Earley States ===\n");
        n00b_parser_print_states(earley, stdout, true);
        printf("\n");

        if (ok) {
            int32_t count = n00b_earley_parse_count(earley);

            if (!dbg->quiet) {
                printf("Parse OK — %d completion(s)\n\n", count);
            }

            n00b_parse_forest_t forest     = n00b_earley_get_forest(earley);
            int32_t             tree_count = n00b_parse_forest_count(&forest);

            if (tree_count > 0) {
                tree = n00b_parse_forest_best(&forest);

                if (!dbg->quiet) {
                    printf("=== Parse Tree ===\n");
                    n00b_tree_print(tree, g, stdout);
                    printf("\n");
                }
            }

            n00b_parse_forest_free(&forest);
        }
        else {
            printf("Parse FAILED.\n");

            n00b_earley_diagnostics_t ediag = {0};
            n00b_earley_extract_diagnostics(earley, &ediag);

            // Build expected-tokens string for the diagnostic.
            char expected_buf[512] = {0};

            if (ediag.expected_count > 0) {
                int off = snprintf(expected_buf, sizeof(expected_buf), "expected");

                for (int32_t i = 0;
                     i < ediag.expected_count && off < (int)sizeof(expected_buf) - 20;
                     i++) {
                    n00b_string_t *tname = n00b_get_terminal_name(g, ediag.expected_ids[i]);

                    if (tname && tname->data) {
                        off += snprintf(expected_buf + off,
                                        sizeof(expected_buf) - (size_t)off,
                                        " %.*s",
                                        (int)tname->u8_bytes,
                                        tname->data);
                    }
                }
            }

            n00b_diag_import_parse_error(diag_ctx,
                                         ediag.error_loc.line,
                                         ediag.error_loc.column,
                                         (ediag.error_loc.got && ediag.error_loc.got->data)
                                             ? ediag.error_loc.got->data
                                             : NULL,
                                         expected_buf[0] ? expected_buf : NULL,
                                         source_file ? source_file->data : NULL);

            if (ediag.expected_ids)
                n00b_free(ediag.expected_ids);
            if (ediag.expected_desc)
                n00b_free(ediag.expected_desc);
            if (ediag.active_ctx)
                n00b_free(ediag.active_ctx);

            n00b_earley_free(earley);

            // Print the diagnostic and exit.
            n00b_diag_print_all(diag_ctx, buf->data, source_file ? source_file->data : NULL);
            n00b_diag_ctx_free(diag_ctx);
            return 1;
        }

        n00b_earley_free(earley);
    }
    else {
        n00b_parse_mode_t mode      = dbg->parse_mode;
        const char       *mode_name = (mode == N00B_PARSE_MODE_EARLEY_ONLY) ? "earley"
                                    : (mode == N00B_PARSE_MODE_PWZ_ONLY)    ? "pwz"
                                                                            : "default";

        if (!dbg->quiet) {
            printf("=== Parse (mode: %s) ===\n", mode_name);
        }

        // Backend was fixed when the grammar was instantiated (from these
        // same debug flags); the parse reads it from the grammar.
        r = n00b_grammar_parse(g, ts);

        if (!n00b_parse_result_ok(r)) {
            n00b_error_location_t eloc     = n00b_parse_result_error_location(r);
            n00b_string_t        *expected = n00b_parse_result_expected_string(r);

            const char *got_str = (eloc.got && eloc.got->data) ? eloc.got->data : NULL;
            char        expected_buf[512] = {0};

            if (expected && expected->u8_bytes > 0) {
                snprintf(expected_buf,
                         sizeof(expected_buf),
                         "expected %.*s",
                         (int)expected->u8_bytes,
                         expected->data);
            }

            n00b_diag_import_parse_error(diag_ctx,
                                         eloc.line,
                                         eloc.column,
                                         got_str,
                                         expected_buf[0] ? expected_buf : NULL,
                                         source_file ? source_file->data : NULL);

            n00b_diag_print_all(diag_ctx, buf->data, source_file ? source_file->data : NULL);
            n00b_parse_result_free(r);
            n00b_diag_ctx_free(diag_ctx);
            return 1;
        }

        tree = n00b_parse_result_tree(r);

        // Check for error-recovered parse. Walk the tree to find error
        // nodes and emit diagnostics, then bail before codegen.
        if (n00b_parse_result_repaired(r)) {
            collect_parse_errors(diag_ctx, g, tree);
            n00b_diag_print_all(diag_ctx, buf->data, source_file ? source_file->data : NULL);
            n00b_parse_result_free(r);
            n00b_diag_ctx_free(diag_ctx);
            return 1;
        }
        int32_t tree_count = n00b_parse_result_tree_count(r);

        if (!dbg->quiet) {
            printf("Parse OK — %d tree(s)%s\n\n",
                   tree_count,
                   n00b_parse_result_ambiguous(r) ? " [AMBIGUOUS]" : "");
            printf("=== Parse Tree ===\n");
            n00b_tree_print(tree, g, stdout);
            printf("\n");
        }
    }

    if (!tree) {
        if (r) {
            n00b_parse_result_free(r);
        }

        return 1;
    }

    if (verbose && !dbg->quiet) {
        n00b_printf("Parsed «#» OK", source_file);
    }

    // Annotation walk.
    n00b_annot_result_t *ar = n00b_compile_walk(g, tree);

    // Import type-check errors into the main diagnostic context.
    if (ar && ar->tc_ctx) {
        n00b_diag_import_tc_errors(diag_ctx, ar->tc_ctx);
    }

    // Merge annotation-walk diagnostics into the main context.
    if (ar && ar->diag) {
        n00b_diag_merge(diag_ctx, ar->diag);
    }

    // Symbol table.
    if (dbg->show_symtab) {
        printf("\n=== Symbol Table ===\n");
        dump_symtab(tree);
        printf("\n");
    }

    // CF labels.
    if (dbg->show_labels && ar && ar->cf_labels) {
        printf("\n=== CF Labels ===\n");
        n00b_cf_labels_print(ar->cf_labels, g, stdout);
        printf("\n");
    }

    // CFG / CDG / DFG + Analysis.
    bool need_graphs = dbg->show_cfg || dbg->show_cdg || dbg->show_dfg || dbg->run_analyze;

    if (need_graphs && ar && ar->cf_labels) {
        n00b_cfg_t *cfg = n00b_build_cfg(ar->cf_labels, tree, r"module", ar->symtab);

        if (cfg) {
            if (dbg->show_cfg) {
                printf("=== CFG ===\n");
                n00b_cfg_print(cfg, g, stdout);
                printf("\n");
            }

            n00b_cdg_t *cdg = NULL;

            if (dbg->show_cdg) {
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

            if (dbg->show_dfg || dbg->run_analyze) {
                dfg = n00b_build_dfg(cfg, ar->cf_labels, g, ar);

                if (dfg && dbg->show_dfg) {
                    printf("=== DFG ===\n");
                    n00b_dfg_print(dfg, g, stdout);
                    printf("\n");
                }
                else if (!dfg) {
                    printf("(DFG build returned NULL)\n");
                }
            }

            // Run analysis.
            if (dbg->run_analyze && dfg) {
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
        else if (!dbg->quiet) {
            printf("(CFG build returned NULL)\n");
        }
    }

    // Bail before codegen if there are any errors from earlier stages.
    if (n00b_diag_has_errors(diag_ctx)) {
        n00b_diag_print_all(diag_ctx, buf->data, source_file->data);
        n00b_diag_ctx_free(diag_ctx);
        return 1;
    }

    // Codegen + JIT + execute.
    n00b_dict_untyped_t *embed_reg = n00b_embed_registry_new();
    n00b_ffi_embed_register(embed_reg);

    n00b_cg_session_t *session
        = n00b_cg_session_new(g, .type_map = n00b_type_map, .embed_registry = embed_reg);

    // Load builtins (print, etc.) before the user module.
    n00b_load_builtins(g, session);

    if (!compile_resolve_source_imports(session, g, source_file, tree, ar)) {
        n00b_diag_ctx_free(diag_ctx);
        return 1;
    }

    bool    run_ok     = false;
    int64_t run_result = n00b_cg_session_run_module(session, tree, .annot = ar, .ok = &run_ok);

    int exit_code;

    // Merge codegen diagnostics into the main context.
    n00b_diag_ctx_t *cg_diag = n00b_codegen_diagnostics(session);

    if (cg_diag) {
        n00b_diag_merge(diag_ctx, cg_diag);
    }

    if (run_ok) {
        if (verbose) {
            n00b_printf("=> «#»", run_result);
        }

        exit_code = (int)run_result;
    }
    else {
        n00b_eprintf("error: codegen/JIT failed for '«#»'", source_file);
        exit_code = 1;
    }

    // Print diagnostics.
    n00b_diag_print_all(diag_ctx, buf->data, source_file->data);

    if (n00b_diag_has_errors(diag_ctx)) {
        exit_code = 1;
    }

    n00b_cg_session_free(session);
    n00b_diag_ctx_free(diag_ctx);

    if (ar && ar->symtab) {
        n00b_symtab_free(ar->symtab);
    }

    if (r) {
        n00b_parse_result_free(r);
    }

    return exit_code;
}

// ============================================================================
// Compile mode: parse → codegen → .o → link
// ============================================================================

static uint64_t
compile_source_hash(n00b_buffer_t *buf)
{
    uint64_t h = 1469598103934665603ULL;

    if (!buf || !buf->data) {
        return h;
    }

    for (uint64_t i = 0; i < buf->byte_len; i++) {
        h ^= (uint8_t)buf->data[i];
        h *= 1099511628211ULL;
    }

    return h;
}

static bool
tree_has_nt(n00b_grammar_t *g, n00b_parse_tree_t *node, const char *nt_name)
{
    (void)g;

    if (!node || !nt_name || n00b_pt_is_token(node)) {
        return false;
    }

    if (n00b_pt_is_nt(node, nt_name)) {
        return true;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        if (tree_has_nt(g, n00b_pt_get_child(node, i), nt_name)) {
            return true;
        }
    }

    return false;
}

static n00b_parse_result_t *
compile_parse_source(n00b_grammar_t *g, n00b_string_t *source_file, n00b_buffer_t *buf)
{
    n00b_scanner_t      *scanner = n00b_scanner_new(buf, n00b_lang_tokenize, g);
    n00b_token_stream_t *ts      = n00b_token_stream_new(scanner);
    n00b_parse_result_t *r       = n00b_grammar_parse(g, ts);

    if (!n00b_parse_result_ok(r)) {
        n00b_string_t *err = n00b_parse_result_error_string(r);
        n00b_eprintf("Parse failed for '«#»': «#»", source_file, err);
        n00b_parse_result_free(r);
        return NULL;
    }

    return r;
}

typedef struct {
    n00b_parse_result_t *parsed;
    n00b_parse_tree_t   *tree;
    n00b_annot_result_t *annot;
    bool                 has_use;
} compile_prepared_source_t;

static compile_prepared_source_t *
compile_prepare_source(n00b_grammar_t *g, n00b_string_t *source_file, n00b_buffer_t *buf)
{
    n00b_parse_result_t *parsed = compile_parse_source(g, source_file, buf);

    if (!parsed) {
        return NULL;
    }

    n00b_parse_tree_t *tree = n00b_parse_result_tree(parsed);

    if (!tree) {
        n00b_parse_result_free(parsed);
        return NULL;
    }

    compile_prepared_source_t *prepared = n00b_alloc(compile_prepared_source_t);
    prepared->parsed                    = parsed;
    prepared->tree                      = tree;
    prepared->has_use                   = tree_has_nt(g, tree, "use-stmt");
    prepared->annot                     = n00b_compile_walk(g, tree);

    return prepared;
}

static void
compile_prepared_source_free(compile_prepared_source_t *prepared)
{
    if (!prepared || !prepared->parsed) {
        return;
    }

    n00b_parse_result_free(prepared->parsed);
    prepared->parsed = NULL;
}

static bool
compile_resolve_source_imports(n00b_cg_session_t   *session,
                               n00b_grammar_t      *g,
                               n00b_string_t       *source_file,
                               n00b_parse_tree_t   *tree,
                               n00b_annot_result_t *annot)
{
    n00b_string_t *source_dir = source_dirname_dup(source_file);

    if (!source_dir) {
        return false;
    }

    bool ok = n00b_resolve_use_stmts(session, g, tree, annot, source_dir);

    return ok;
}

static bool
compile_reject_use_if_present(n00b_grammar_t            *g,
                              n00b_string_t             *source_file,
                              compile_prepared_source_t *prepared)
{
    (void)g;

    if (!prepared || !prepared->has_use) {
        return true;
    }

    fprintf(stderr,
            "error: compile mode does not support `use` imports yet for '%.*s'\n",
            (int)source_file->u8_bytes,
            source_file->data);
    return false;
}

#ifdef _WIN32
static bool
compile_windows_path_is_reparse_point(const char *path, bool *is_reparse)
{
    WIN32_FIND_DATAA data = {};
    HANDLE h = FindFirstFileA(path, &data);

    if (h == INVALID_HANDLE_VALUE) {
        errno = ENOENT;
        return false;
    }

    (void)FindClose(h);
    *is_reparse = (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    return true;
}

static int
compile_cache_open_read(const char *path)
{
    bool is_reparse = false;

    if (!compile_windows_path_is_reparse_point(path, &is_reparse)) {
        return -1;
    }
    if (is_reparse) {
        errno = ELOOP;
        return -1;
    }

    return _open(path, _O_RDONLY | _O_BINARY);
}

static int
compile_cache_open_new(const char *path)
{
    return _open(path,
                 _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY,
                 _S_IREAD | _S_IWRITE);
}
#else
static int
compile_cache_open_read(const char *path)
{
    return open(path, O_RDONLY | O_NOFOLLOW);
}

static int
compile_cache_open_new(const char *path)
{
    return open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
}
#endif
static bool
compile_ensure_cache_dir(const char *cache_dir)
{
    if (!cache_dir || !*cache_dir) {
        return false;
    }

    if (mkdir(cache_dir, 0700) == 0) {
        return true;
    }

    if (errno == EEXIST) {
        struct stat st;
#ifdef _WIN32
        bool is_reparse = false;
        if (!compile_windows_path_is_reparse_point(cache_dir, &is_reparse)
            || is_reparse) {
            return false;
        }
        return stat(cache_dir, &st) == 0 && S_ISDIR(st.st_mode);
#else
        return lstat(cache_dir, &st) == 0 && S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode);
#endif
    }

    return false;
}

static bool
compile_cache_path(char *buf, size_t buf_len, const char *cache_dir, uint64_t hash)
{
    const char *sep = "/";
    size_t      len = strlen(cache_dir);

    if (len > 0 && (cache_dir[len - 1] == '/' || cache_dir[len - 1] == '\\')) {
        sep = "";
    }

    int n = snprintf(buf,
                     buf_len,
                     "%s%s%016llx.n00bcache",
                     cache_dir,
                     sep,
                     (unsigned long long)hash);

    return n > 0 && (size_t)n < buf_len;
}

static bool
compile_cache_hit(const char *path, uint64_t hash, uint64_t size)
{
    int fd = compile_cache_open_read(path);

    if (fd < 0) {
        return false;
    }

    FILE *fp = fdopen(fd, "r");

    if (!fp) {
        close(fd);
        return false;
    }

    char               line[512];
    bool               saw_magic          = false;
    bool               saw_source         = false;
    bool               saw_module         = false;
    bool               saw_hash           = false;
    bool               saw_size           = false;
    bool               saw_public_symbols = false;
    bool               saw_dependencies   = false;
    bool               saw_ffi            = false;
    uint64_t           got_hash           = 0;
    uint64_t           got_size           = 0;
    unsigned long long parsed;

    while (fgets(line, sizeof(line), fp)) {
        if (strcmp(line, "N00B_MIR_CACHE_V1\n") == 0) {
            saw_magic = true;
        }
        else if (strncmp(line, "source=", 7) == 0) {
            saw_source = true;
        }
        else if (strcmp(line, "module=_main\n") == 0) {
            saw_module = true;
        }
        else if (sscanf(line, "hash=%llx", &parsed) == 1) {
            got_hash = (uint64_t)parsed;
            saw_hash = true;
        }
        else if (sscanf(line, "size=%llu", &parsed) == 1) {
            got_size = (uint64_t)parsed;
            saw_size = true;
        }
        else if (strncmp(line, "public_symbols=", 15) == 0) {
            saw_public_symbols = true;
        }
        else if (strncmp(line, "dependencies=", 13) == 0) {
            saw_dependencies = true;
        }
        else if (strncmp(line, "ffi_declarations=", 17) == 0) {
            saw_ffi = true;
        }
    }

    bool read_ok = !ferror(fp);

    if (fclose(fp) != 0) {
        read_ok = false;
    }

    return read_ok && saw_magic && saw_source && saw_module && saw_hash && saw_size
        && saw_public_symbols && saw_dependencies && saw_ffi && got_hash == hash
        && got_size == size;
}

static bool
compile_cache_write(const char *path, n00b_string_t *source_file, uint64_t hash, uint64_t size)
{
    char tmp_path[1088];
    int  fd = -1;

    for (int i = 0; i < 100; i++) {
        int n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%ld.%d", path, (long)getpid(), i);

        if (n <= 0 || (size_t)n >= sizeof(tmp_path)) {
            return false;
        }

        fd = compile_cache_open_new(tmp_path);

        if (fd >= 0) {
            break;
        }

        if (errno != EEXIST) {
            return false;
        }
    }

    if (fd < 0) {
        return false;
    }

    FILE *fp = fdopen(fd, "w");

    if (!fp) {
        close(fd);
        unlink(tmp_path);
        return false;
    }

    bool ok = fprintf(fp, "N00B_MIR_CACHE_V1\n") >= 0
           && fprintf(fp, "source=%.*s\n", (int)source_file->u8_bytes, source_file->data) >= 0
           && fprintf(fp, "module=_main\n") >= 0
           && fprintf(fp, "hash=%016llx\n", (unsigned long long)hash) >= 0
           && fprintf(fp, "size=%llu\n", (unsigned long long)size) >= 0
           && fprintf(fp, "public_symbols=_main\n") >= 0 && fprintf(fp, "dependencies=\n") >= 0
           && fprintf(fp, "ffi_declarations=\n") >= 0;

    if (fclose(fp) != 0) {
        ok = false;
    }

    if (!ok) {
        unlink(tmp_path);
        return false;
    }

    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        return false;
    }

    return true;
}

static bool
compile_cache_build(n00b_grammar_t            *g,
                    n00b_cg_session_t         *session,
                    n00b_string_t             *source_file,
                    compile_prepared_source_t *prepared)
{
    if (!prepared) {
        return false;
    }

    if (!compile_resolve_source_imports(session,
                                        g,
                                        source_file,
                                        prepared->tree,
                                        prepared->annot)) {
        return false;
    }

    n00b_module_code_t *mod
        = n00b_cg_session_compile_module(session, prepared->tree, .annot = prepared->annot);
    bool ok = mod != NULL;

    if (!ok) {
        n00b_eprintf("error: codegen failed for '«#»'", source_file);
    }

    return ok;
}

static bool
compile_cache_process(n00b_grammar_t    *g,
                      n00b_cg_session_t *session,
                      n00b_string_t     *source_file,
                      n00b_buffer_t     *buf,
                      const char        *cache_dir,
                      bool               verbose)
{
    if (!compile_ensure_cache_dir(cache_dir)) {
        n00b_eprintf("error: cannot create compile cache directory");
        return false;
    }

    uint64_t hash = compile_source_hash(buf);
    uint64_t size = buf ? buf->byte_len : 0;
    char     path[1024];

    if (!compile_cache_path(path, sizeof(path), cache_dir, hash)) {
        n00b_eprintf("error: compile cache path is too long");
        return false;
    }

    if (compile_cache_hit(path, hash, size)) {
        if (verbose) {
            printf("cache restored %s\n", path);
        }

        return true;
    }

    compile_prepared_source_t *prepared = compile_prepare_source(g, source_file, buf);

    if (!prepared) {
        return false;
    }

    if (!compile_reject_use_if_present(g, source_file, prepared)) {
        compile_prepared_source_free(prepared);
        return false;
    }

    bool built = compile_cache_build(g, session, source_file, prepared);
    compile_prepared_source_free(prepared);

    if (!built) {
        return false;
    }

    if (!compile_cache_write(path, source_file, hash, size)) {
        n00b_eprintf("error: cannot write compile cache artifact");
        return false;
    }

    if (verbose) {
        printf("cache stored %s\n", path);
    }

    return true;
}

static int
compile_files(n00b_grammar_t *g, n00b_cmdr_result_t *result, bool verbose)
{
#ifdef _WIN32
    (void)g;
    (void)result;
    (void)verbose;
    fprintf(stderr, "error: compile mode is not supported on Windows yet\n");
    return 1;
#endif

    int            nargs        = n00b_cmdr_arg_count(result);
    n00b_string_t *output       = n00b_cmdr_flag_str(result, r"--output");
    n00b_string_t *lib_dir_s    = n00b_cmdr_flag_str(result, r"--lib-dir");
    n00b_string_t *cache_dir_s  = n00b_cmdr_flag_str(result, r"--cache-dir");
    bool           keep_objects = n00b_cmdr_flag_bool(result, r"--keep-objects");
    bool           cache_only   = n00b_cmdr_flag_bool(result, r"--cache-only");

    if (nargs > 1) {
        fprintf(stderr,
                "error: compile mode currently supports exactly one input file; got %d\n",
                nargs);
        return 1;
    }

    const char *lib_dir = (lib_dir_s && lib_dir_s->u8_bytes > 0) ? lib_dir_s->data : NULL;
    const char *cache_dir
        = (cache_dir_s && cache_dir_s->u8_bytes > 0) ? cache_dir_s->data : ".n00b-cache";

    // Default output name: first source file with extension stripped.
    char output_path[1024];

    if (output && output->u8_bytes > 0) {
        snprintf(output_path, sizeof(output_path), "%.*s", (int)output->u8_bytes, output->data);
    }
    else {
        n00b_string_t *first = n00b_cmdr_arg_str(result, 0);
        snprintf(output_path, sizeof(output_path), "%.*s", (int)first->u8_bytes, first->data);

        // Strip .n extension.
        char *dot = strrchr(output_path, '.');

        if (dot) {
            *dot = '\0';
        }

#ifdef _WIN32
        strncat(output_path, ".exe", sizeof(output_path) - strlen(output_path) - 1);
#endif
    }

    // Allocate arrays for object file paths.
    // +1 for the startup shim.
    const char **obj_paths   = n00b_alloc_array(const char *, nargs + 1);
    char       **obj_paths_m = n00b_alloc_array(char *, nargs + 1);
    int          n_objs      = 0;

    // Create a codegen session with FFI embed support.
    n00b_dict_untyped_t *compile_embed_reg = n00b_embed_registry_new();
    n00b_ffi_embed_register(compile_embed_reg);

    n00b_cg_session_t *session = n00b_cg_session_new(g,
                                                     .type_map       = n00b_type_map,
                                                     .embed_registry = compile_embed_reg);

    // Load builtins (print, etc.) before user modules.
    n00b_load_builtins(g, session);

    // Compile each source file.
    for (int i = 0; i < nargs; i++) {
        n00b_string_t *source_file = n00b_cmdr_arg_str(result, i);
        n00b_buffer_t *buf         = read_source_file(source_file);

        if (!buf) {
            n00b_eprintf("error: cannot read '«#»'", source_file);
            goto fail;
        }

        if (cache_only) {
            if (!compile_cache_process(g, session, source_file, buf, cache_dir, verbose)) {
                goto fail;
            }

            continue;
        }

        compile_prepared_source_t *prepared = compile_prepare_source(g, source_file, buf);

        if (!prepared) {
            goto fail;
        }

        if (!compile_reject_use_if_present(g, source_file, prepared)) {
            compile_prepared_source_free(prepared);
            goto fail;
        }

        if (!compile_resolve_source_imports(session,
                                            g,
                                            source_file,
                                            prepared->tree,
                                            prepared->annot)) {
            compile_prepared_source_free(prepared);
            goto fail;
        }

        // Compile to machine code.
        n00b_module_code_t *mod
            = n00b_cg_session_compile_module(session, prepared->tree, .annot = prepared->annot);

        if (!mod) {
            n00b_eprintf("error: codegen failed for '«#»'", source_file);
            compile_prepared_source_free(prepared);
            goto fail;
        }

        // Emit .o file.
        n00b_buffer_t *obj_buf = n00b_emit_object_file(mod);

        if (!obj_buf) {
            n00b_eprintf("error: object file emission failed for '«#»'", source_file);
            compile_prepared_source_free(prepared);
            goto fail;
        }

        // Write .o to a temp file.
        char obj_path[1024];

        if (!compile_temp_path(obj_path, sizeof(obj_path), "module", i, ".o")) {
            n00b_eprintf("error: cannot create temporary object path");
            compile_prepared_source_free(prepared);
            goto fail;
        }

        FILE *fp = fopen(obj_path, "wb");

        if (!fp) {
            n00b_eprintf("error: cannot write '«#»'", n00b_string_from_cstr(obj_path));
            compile_prepared_source_free(prepared);
            goto fail;
        }

        fwrite(obj_buf->data, 1, obj_buf->byte_len, fp);
        fclose(fp);

        // GC-managed string copy of obj_path.
        size_t opl = strlen(obj_path);
        char  *dup = n00b_alloc_array(char, opl + 1);
        memcpy(dup, obj_path, opl + 1);
        obj_paths_m[n_objs] = dup;
        obj_paths[n_objs]   = dup;
        n_objs++;

        compile_prepared_source_free(prepared);

        if (verbose) {
            printf("  compiled %.*s -> %s\n",
                   (int)source_file->u8_bytes,
                   source_file->data,
                   obj_path);
        }
    }

    if (cache_only) {
        /* obj_paths and obj_paths_m are GC-managed. */
        n00b_cg_session_free(session);
        return 0;
    }

    // Generate startup shim.
    {
        const char *startup_src
            = "#include <stdint.h>\n"
              "extern void n00b_init_simple(int, char**);\n"
              "extern void n00b_shutdown_simple(void);\n"
              "extern int64_t _main(void);\n"
              "int main(int argc, char **argv) {\n"
              "    n00b_init_simple(argc, argv);\n"
              "    int64_t r = _main();\n"
              "    n00b_shutdown_simple();\n"
              "    return (int)r;\n"
              "}\n";

        // Write startup source to temp file.
        char startup_c_buf[1024];
        char startup_o_buf[1024];

        if (!compile_temp_path(startup_c_buf, sizeof(startup_c_buf), "startup", 0, ".c")
            || !compile_temp_path(startup_o_buf, sizeof(startup_o_buf), "startup", 0, ".o")) {
            n00b_eprintf("error: cannot create temporary startup path");
            goto fail;
        }

        const char *startup_c = startup_c_buf;
        FILE       *fp        = fopen(startup_c, "w");

        if (!fp) {
            n00b_eprintf("error: cannot write startup shim");
            goto fail;
        }

        fputs(startup_src, fp);
        fclose(fp);

        // Compile startup shim via clang.
        const char *startup_o = startup_o_buf;
        const char *compiler  = compile_compiler();

        const char *argv[8];
        int         ai = 0;

        argv[ai++] = compiler;
#ifdef _WIN32
        argv[ai++] = "--target=x86_64-w64-windows-gnu";
#endif
        argv[ai++] = "-c";
        argv[ai++] = "-o";
        argv[ai++] = startup_o;
        argv[ai++] = startup_c;
        argv[ai]   = NULL;

        if (compile_spawn_wait(argv) != 0) {
            n00b_eprintf("error: startup shim compilation failed");
            goto fail;
        }

        size_t sol = strlen(startup_o);
        char  *sdup = n00b_alloc_array(char, sol + 1);
        memcpy(sdup, startup_o, sol + 1);
        obj_paths_m[n_objs] = sdup;
        obj_paths[n_objs]   = sdup;
        n_objs++;

        // Clean up temp .c file.
        remove(startup_c);
    }

    // Link everything.
    {
        int rc = n00b_link_binary(obj_paths, n_objs, output_path, lib_dir);

        if (rc != 0) {
            fprintf(stderr, "error: linking failed (exit code %d)\n", rc);
            goto fail;
        }

        if (verbose) {
            printf("  linked -> %s\n", output_path);
        }
    }

    // Clean up temp .o files.
    if (!keep_objects) {
        for (int i = 0; i < n_objs; i++) {
            remove(obj_paths[i]);
        }
    }
    else {
        printf("Object files:\n");

        for (int i = 0; i < n_objs; i++) {
            printf("  %s\n", obj_paths[i]);
        }
    }

    for (int i = 0; i < n_objs; i++) {
        /* obj_paths_m[i] is GC-managed. */
    }

    /* obj_paths is GC-managed. */
    /* obj_paths_m is GC-managed. */
    n00b_cg_session_free(session);
    return 0;

fail:
    for (int i = 0; i < n_objs; i++) {
        if (!keep_objects) {
            remove(obj_paths[i]);
        }

        /* obj_paths_m[i] is GC-managed. */
    }

    /* obj_paths is GC-managed. */
    /* obj_paths_m is GC-managed. */
    n00b_cg_session_free(session);
    return 1;
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    n00b_cmdr_t *cmdr = build_commander();

    // No arguments → default to repl mode.
    if (argc <= 1) {
        n00b_grammar_t *g = load_n00b_grammar(NULL, N00B_PARSE_MODE_DEFAULT);

        if (!g) {
            n00b_cmdr_free(cmdr);
            n00b_shutdown();
            return 1;
        }

        int rc = n00b_repl_run(g);
        n00b_grammar_free(g);
        n00b_cmdr_free(cmdr);
        n00b_shutdown();
        return rc;
    }

    n00b_cmdr_result_t *result = n00b_cmdr_parse(cmdr, argc - 1, (const char **)&argv[1]);

    if (!result || !result->ok) {
        int32_t nerr = n00b_cmdr_error_count(result);

        for (int32_t i = 0; i < nerr; i++) {
            n00b_string_t *err = n00b_cmdr_error_get(result, i);
            n00b_eprintf("n00b: «#»", err);
        }

        print_usage();
        n00b_cmdr_result_free(result);
        n00b_cmdr_free(cmdr);
        n00b_shutdown();
        return 1;
    }

    // Handle --help.
    if (n00b_cmdr_flag_bool(result, r"--help")) {
        print_usage();
        n00b_cmdr_result_free(result);
        n00b_cmdr_free(cmdr);
        n00b_shutdown();
        return 0;
    }

    // Handle --version.
    if (n00b_cmdr_flag_bool(result, r"--version")) {
        print_version();
        n00b_cmdr_result_free(result);
        n00b_cmdr_free(cmdr);
        n00b_shutdown();
        return 0;
    }

    // Determine mode from subcommand, default to "repl".
    n00b_string_t *cmd  = n00b_cmdr_result_command(result);
    const char    *mode = "repl";

    if (cmd && cmd->u8_bytes > 0) {
        mode = cmd->data;
    }

    bool    verbose = n00b_cmdr_flag_bool(result, r"--verbose");
    int32_t nargs   = n00b_cmdr_arg_count(result);

    // Extract debug flags.
    debug_opts_t dbg = {0};

    dbg.show_tokens   = n00b_cmdr_flag_bool(result, r"--debug-tokens");
    dbg.show_grammar  = n00b_cmdr_flag_bool(result, r"--debug-grammar");
    dbg.show_states   = n00b_cmdr_flag_bool(result, r"--debug-states");
    dbg.show_lr0      = n00b_cmdr_flag_bool(result, r"--debug-lr0");
    dbg.show_cfg      = n00b_cmdr_flag_bool(result, r"--debug-cfg");
    dbg.show_cdg      = n00b_cmdr_flag_bool(result, r"--debug-cdg");
    dbg.show_dfg      = n00b_cmdr_flag_bool(result, r"--debug-dfg");
    dbg.show_labels   = n00b_cmdr_flag_bool(result, r"--debug-labels");
    dbg.show_symtab   = n00b_cmdr_flag_bool(result, r"--debug-symtab");
    dbg.run_analyze   = n00b_cmdr_flag_bool(result, r"--debug-analyze");
    dbg.run_typecheck = n00b_cmdr_flag_bool(result, r"--debug-typecheck");
    dbg.quiet         = n00b_cmdr_flag_bool(result, r"--quiet");
    dbg.parse_mode    = N00B_PARSE_MODE_DEFAULT;

    if (n00b_cmdr_flag_bool(result, r"--debug-earley")) {
        dbg.parse_mode = N00B_PARSE_MODE_EARLEY_ONLY;
    }
    else if (n00b_cmdr_flag_bool(result, r"--debug-pwz")) {
        dbg.parse_mode = N00B_PARSE_MODE_PWZ_ONLY;
    }

    // --debug-all enables all debug outputs.
    if (n00b_cmdr_flag_bool(result, r"--debug-all")) {
        dbg.show_tokens   = true;
        dbg.show_grammar  = true;
        dbg.show_states   = true;
        dbg.show_lr0      = true;
        dbg.show_cfg      = true;
        dbg.show_cdg      = true;
        dbg.show_dfg      = true;
        dbg.show_labels   = true;
        dbg.show_symtab   = true;
        dbg.run_analyze   = true;
        dbg.run_typecheck = true;
    }

    n00b_string_t *grammar_file = n00b_cmdr_flag_str(result, r"--debug-grammar-file");

    // help subcommand.
    if (strcmp(mode, "help") == 0) {
        print_usage();
        n00b_cmdr_result_free(result);
        n00b_cmdr_free(cmdr);
        n00b_shutdown();
        return 0;
    }

    // compile subcommand.
    if (strcmp(mode, "compile") == 0) {
#ifdef _WIN32
        fprintf(stderr, "error: compile mode is not supported on Windows yet\n");
        n00b_cmdr_result_free(result);
        n00b_cmdr_free(cmdr);
        n00b_shutdown();
        return 1;
#endif

        n00b_grammar_t *g = load_n00b_grammar(grammar_file, N00B_PARSE_MODE_DEFAULT);

        if (!g) {
            n00b_cmdr_result_free(result);
            n00b_cmdr_free(cmdr);
            n00b_shutdown();
            return 1;
        }

        int rc = compile_files(g, result, verbose);
        n00b_grammar_free(g);
        n00b_cmdr_result_free(result);
        n00b_cmdr_free(cmdr);
        n00b_shutdown();
        return rc;
    }

    // run subcommand or default repl-with-files: JIT all files, execute
    // the first one.
    if (strcmp(mode, "run") == 0 || (strcmp(mode, "repl") == 0 && nargs > 0)) {
        if (nargs == 0) {
            n00b_eprintf("error: 'run' requires at least one source file");
            n00b_cmdr_result_free(result);
            n00b_cmdr_free(cmdr);
            n00b_shutdown();
            return 1;
        }

        // Load grammar once for all files. Backend selection comes from the
        // debug flags (--pwz/--earley) and is fixed at instantiation.
        n00b_grammar_t *g = load_n00b_grammar(grammar_file, dbg.parse_mode);

        if (!g) {
            n00b_cmdr_result_free(result);
            n00b_cmdr_free(cmdr);
            n00b_shutdown();
            return 1;
        }

        // Run the first file.  (Future: JIT all files into one session,
        // then execute the first file's _main.)
        n00b_string_t *first     = n00b_cmdr_arg_str(result, 0);
        int            exit_code = run_file(g, first, verbose, &dbg);

        n00b_grammar_free(g);
        n00b_cmdr_result_free(result);
        n00b_cmdr_free(cmdr);
        n00b_shutdown();
        return exit_code;
    }

    // Bare repl mode (no files).
    {
        n00b_grammar_t *g = load_n00b_grammar(grammar_file, N00B_PARSE_MODE_DEFAULT);

        if (!g) {
            n00b_cmdr_result_free(result);
            n00b_cmdr_free(cmdr);
            n00b_shutdown();
            return 1;
        }

        int rc = n00b_repl_run(g);
        n00b_grammar_free(g);
        n00b_cmdr_result_free(result);
        n00b_cmdr_free(cmdr);
        n00b_shutdown();
        return rc;
    }
}

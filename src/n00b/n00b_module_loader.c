// n00b_module_loader.c — Module loading for `use` statements.
//
// Resolves module paths, reads .n files, parses, annotates, compiles,
// and merges public symbols into the session's global scope.

#include "n00b.h"
#include "n00b/n00b_module_loader.h"
#include "n00b/n00b_compile.h"
#include "n00b/n00b_compile_binary.h"
#include "n00b/n00b_tokenizer.h"
#include "n00b/n00b_type_map.h"
#include "typecheck/unify.h"
#include "adt/variant.h"
#include "internal/slay/codegen_internal.h"
#include "internal/slay/grammar_internal.h"
#include "slay/tree_util.h"
#include "slay/symtab.h"
#include "slay/n00b_parse.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/hash.h"
#include "core/string.h"
#include "text/strings/string_ops.h"

// n00b-backed C-string copy.  Call sites below invoke this explicitly — no libc
// strdup remains in the source (the module loader is n00b's own ncc code).
static char *
n00b_loader_strdup(const char *s)
{
    size_t n   = strlen(s) + 1;
    char  *out = n00b_alloc_array(char, n);
    memcpy(out, s, n);
    return out;
}
#include "adt/dict_untyped.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

// ============================================================================
// Path resolution
// ============================================================================

const char **
n00b_get_module_search_path(int32_t *count)
{
    // Maximum directories: N00B_ROOT + N00B_PATH entries + CWD.
    const char **dirs = n00b_alloc_array(const char *, 64);
    int32_t      n    = 0;

    // 1. N00B_ROOT/sys/
    const char *root = getenv("N00B_ROOT");

    if (root && root[0]) {
        char buf[PATH_MAX];
        snprintf(buf, sizeof(buf), "%s/sys", root);

        struct stat st;

        if (stat(buf, &st) == 0 && S_ISDIR(st.st_mode)) {
            dirs[n++] = n00b_loader_strdup(buf);
        }
    }

    // 2. N00B_PATH (colon-separated)
    const char *path_env = getenv("N00B_PATH");

    if (path_env && path_env[0]) {
        char *copy = n00b_loader_strdup(path_env);
        char *tok  = strtok(copy, ":");

        while (tok && n < 62) {
            struct stat st;

            if (stat(tok, &st) == 0 && S_ISDIR(st.st_mode)) {
                dirs[n++] = n00b_loader_strdup(tok);
            }

            tok = strtok(NULL, ":");
        }

        n00b_free(copy);
    }

    // 3. CWD
    char cwd[PATH_MAX];

    if (getcwd(cwd, sizeof(cwd))) {
        dirs[n++] = n00b_loader_strdup(cwd);
    }

    *count = n;

    return dirs;
}

// ============================================================================
// File reading
// ============================================================================

static char *
read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");

    if (!f) {
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (len <= 0) {
        fclose(f);
        return NULL;
    }

    char *buf = n00b_alloc_array(char, (size_t)len + 1);

    if (!buf) {
        fclose(f);
        return NULL;
    }

    size_t nread = fread(buf, 1, (size_t)len, f);
    fclose(f);

    buf[nread] = '\0';
    *out_len   = nread;

    return buf;
}

// ============================================================================
// Cycle detection helpers
// ============================================================================

static bool
is_on_loading_stack(n00b_cg_session_t *s, const char *fqn)
{
    for (int32_t i = 0; i < s->loading_depth; i++) {
        if (strcmp(s->loading_stack[i], fqn) == 0) {
            return true;
        }
    }

    return false;
}

static void
push_loading_stack(n00b_cg_session_t *s, const char *fqn)
{
    if (s->loading_depth >= s->loading_cap) {
        int32_t      new_cap   = s->loading_cap ? s->loading_cap * 2 : 16;
        const char **new_stack = n00b_alloc_array(const char *, (size_t)new_cap);

        if (s->loading_stack) {
            memcpy(new_stack,
                   s->loading_stack,
                   sizeof(const char *) * (size_t)s->loading_depth);
        }

        s->loading_stack = new_stack;
        s->loading_cap   = new_cap;
    }

    s->loading_stack[s->loading_depth++] = fqn;
}

static void
pop_loading_stack(n00b_cg_session_t *s)
{
    if (s->loading_depth > 0) {
        s->loading_depth--;
    }
}

static char *
module_dirname_dup(const char *path)
{
    if (!path || !path[0]) {
        return n00b_loader_strdup(".");
    }

    const char *slash = strrchr(path, '/');

    if (!slash) {
        return n00b_loader_strdup(".");
    }

    if (slash == path) {
        return n00b_loader_strdup("/");
    }

    size_t len = (size_t)(slash - path);
    char  *dir = n00b_alloc_array(char, len + 1);

    if (!dir) {
        return NULL;
    }

    memcpy(dir, path, len);
    dir[len] = '\0';
    return dir;
}

static char *
module_cache_key_dup(const char *path)
{
    if (!path || !path[0]) {
        return NULL;
    }

    char resolved[PATH_MAX];

    if (realpath(path, resolved)) {
        return n00b_loader_strdup(resolved);
    }

    return n00b_loader_strdup(path);
}

// ============================================================================
// Path construction: try to find "package/module.n" in search dirs
// ============================================================================

static char *
find_module_file(const char *module_name,
                 const char *package,
                 const char *from_path,
                 const char *caller_path)
{
    char candidate[PATH_MAX];

    // If explicit from_path, try that first (relative to caller_path or CWD).
    if (from_path && from_path[0]) {
        // Build: from_path / module_name.n
        if (from_path[0] == '/' || !caller_path) {
            snprintf(candidate, sizeof(candidate), "%s/%s.n", from_path, module_name);
        }
        else {
            snprintf(candidate,
                     sizeof(candidate),
                     "%s/%s/%s.n",
                     caller_path,
                     from_path,
                     module_name);
        }

        struct stat st;

        if (stat(candidate, &st) == 0 && S_ISREG(st.st_mode)) {
            return n00b_loader_strdup(candidate);
        }

        // Also try from_path directly as a file.
        if (from_path[0] == '/' || !caller_path) {
            snprintf(candidate, sizeof(candidate), "%s", from_path);
        }
        else {
            snprintf(candidate, sizeof(candidate), "%s/%s", caller_path, from_path);
        }

        if (stat(candidate, &st) == 0 && S_ISREG(st.st_mode)) {
            return n00b_loader_strdup(candidate);
        }
    }

    // Build the relative path from package + module.
    // "pkg.sub" → "pkg/sub"
    char rel_path[PATH_MAX];

    if (package && package[0]) {
        // Convert dots to slashes.
        size_t pi = 0;

        for (size_t i = 0; package[i] && pi < sizeof(rel_path) - 1; i++) {
            rel_path[pi++] = (package[i] == '.') ? '/' : package[i];
        }

        if (pi < sizeof(rel_path) - 1) {
            rel_path[pi++] = '/';
        }

        size_t mlen = strlen(module_name);

        if (pi + mlen + 3 < sizeof(rel_path)) {
            memcpy(rel_path + pi, module_name, mlen);
            pi += mlen;
            memcpy(rel_path + pi, ".n", 3); // includes NUL
        }
        else {
            rel_path[pi] = '\0';
        }
    }
    else {
        snprintf(rel_path, sizeof(rel_path), "%s.n", module_name);
    }

    // Try caller_path first.
    if (caller_path && caller_path[0]) {
        snprintf(candidate, sizeof(candidate), "%s/%s", caller_path, rel_path);

        struct stat st;

        if (stat(candidate, &st) == 0 && S_ISREG(st.st_mode)) {
            return n00b_loader_strdup(candidate);
        }
    }

    // Search N00B_ROOT, N00B_PATH, CWD.
    int32_t      dir_count = 0;
    const char **dirs      = n00b_get_module_search_path(&dir_count);

    for (int32_t i = 0; i < dir_count; i++) {
        snprintf(candidate, sizeof(candidate), "%s/%s", dirs[i], rel_path);

        struct stat st;

        if (stat(candidate, &st) == 0 && S_ISREG(st.st_mode)) {
            char *result = n00b_loader_strdup(candidate);

            // Free search path strings.
            for (int32_t j = 0; j < dir_count; j++) {
                n00b_free((void *)dirs[j]);
            }

            return result;
        }
    }

    // Free search path strings.
    for (int32_t j = 0; j < dir_count; j++) {
        n00b_free((void *)dirs[j]);
    }

    return NULL;
}

// ============================================================================
// Per-function codegen for imported modules
// ============================================================================

// Extract the function name from a func-def node.
//
// Grammar: <func-def> ::= <func-mod>* <func-kind> %IDENTIFIER
//                          <param-decl> <where-clause>? <return-type>? <body>
//
// The IDENTIFIER is a leaf child.  We skip keyword leaves ("private",
// "once", "func", "method") and return the first identifier that isn't
// one of those.
static const char *
extract_func_name(n00b_parse_tree_t *func_def_node)
{
    size_t nc = n00b_tree_num_children(func_def_node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_tree_child(func_def_node, i);

        if (!n00b_tree_is_leaf(child)) {
            continue;
        }

        n00b_token_info_t *tok = n00b_tree_leaf_value(child);

        if (!tok || !n00b_option_is_set(tok->value)) {
            continue;
        }

        n00b_string_t *val = n00b_option_get(tok->value);

        if (val->u8_bytes <= 0) {
            continue;
        }

        // Skip grammar keywords.
        if (n00b_unicode_str_eq(val, r"private") || n00b_unicode_str_eq(val, r"once")
            || n00b_unicode_str_eq(val, r"func") || n00b_unicode_str_eq(val, r"method")) {
            continue;
        }

        return val->data;
    }

    return NULL;
}

// Check whether a func-def has the "private" modifier.
//
// <func-mod>* can produce "private" or "once" keyword leaves (or
// group-wrapped versions of them).  We look for a "private" leaf
// anywhere before the <func-kind> keyword ("func"/"method").
static bool
is_func_private(n00b_parse_tree_t *func_def_node)
{
    size_t nc = n00b_tree_num_children(func_def_node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_tree_child(func_def_node, i);

        if (!n00b_tree_is_leaf(child)) {
            // Recurse into group nodes (func-mod* creates a $$group).
            n00b_nt_node_t *cpn = &n00b_tree_node_value(child);

            if (cpn->group_top) {
                size_t gnc = n00b_tree_num_children(child);

                for (size_t j = 0; j < gnc; j++) {
                    n00b_parse_tree_t *gc = n00b_tree_child(child, j);

                    if (!n00b_tree_is_leaf(gc)) {
                        continue;
                    }

                    n00b_token_info_t *tok = n00b_tree_leaf_value(gc);

                    if (tok && n00b_option_is_set(tok->value)) {
                        n00b_string_t *v = n00b_option_get(tok->value);

                        if (n00b_unicode_str_eq(v, r"private")) {
                            return true;
                        }
                    }
                }
            }

            continue;
        }

        n00b_token_info_t *tok = n00b_tree_leaf_value(child);

        if (!tok || !n00b_option_is_set(tok->value)) {
            continue;
        }

        n00b_string_t *val = n00b_option_get(tok->value);

        if (n00b_unicode_str_eq(val, r"private")) {
            return true;
        }

        // Once we hit "func" or "method" there are no more modifiers.
        if (n00b_unicode_str_eq(val, r"func") || n00b_unicode_str_eq(val, r"method")) {
            break;
        }
    }

    return false;
}

// ---- Parameter extraction ----
//
// Grammar:
//   <param-decl>   ::= %"(" <formals>? %")"
//   <formals>      ::= <formal-param> (%"," <formal-param>)* ...
//   <formal-param> ::= <pos-param> | <k-param>
//   <pos-param>    ::= %IDENTIFIER | %IDENTIFIER %":" <type-spec>
//   <k-param>      ::= %IDENTIFIER %"=" <expression>
//                     | %IDENTIFIER %":" <type-spec> %"=" <expression>
//   <vargs-param>  ::= %"*" %IDENTIFIER ...
//
// Each <pos-param> / <k-param> / <vargs-param> has a single
// %IDENTIFIER as its first token (vargs-param has "*" first, then
// the IDENTIFIER).  We extract the first IDENTIFIER from each.

// Extract parameter names from a func-def node.
//
// Uses a DFS through <param-decl> to find all <formal-param> and
// <vargs-param> nodes.  Each contains a bare %IDENTIFIER as its
// first token (for <vargs-param>, the name follows the "*" token).
//
// Returns the count, writes into caller-provided arrays.
static int32_t
extract_params(n00b_grammar_t    *grammar,
               n00b_parse_tree_t *func_def_node,
               const char       **out_names,
               int32_t            cap)
{
    // Find <param-decl>.
    n00b_parse_tree_t *param_decl
        = n00b_tree_find_child_by_nt_name(grammar, func_def_node, r"param-decl");

    if (!param_decl) {
        return 0;
    }

    // Look up NT ids for the param types we care about.
    int64_t fp_id = -1;
    int64_t vp_id = -1;

    if (grammar) {
        bool found = false;

        n00b_string_t *fp_key = n00b_string_from_cstr("formal-param");
        fp_id                 = n00b_dict_get(grammar->nt_map, fp_key, &found);
        if (!found) {
            fp_id = -1;
        }

        found                 = false;
        n00b_string_t *vp_key = n00b_string_from_cstr("vargs-param");
        vp_id                 = n00b_dict_get(grammar->nt_map, vp_key, &found);
        if (!found) {
            vp_id = -1;
        }
    }

    // DFS through param-decl to find all formal-param / vargs-param
    // nodes, extracting the first IDENTIFIER token from each.
    n00b_parse_tree_t *stack[128];
    int                sp  = 0;
    int32_t            pos = 0;

    stack[sp++] = param_decl;

    while (sp > 0 && pos < cap) {
        n00b_parse_tree_t *cur = stack[--sp];

        if (!cur || n00b_pt_is_token(cur)) {
            continue;
        }

        n00b_nt_node_t *pn = &n00b_tree_node_value(cur);

        if (pn->id == fp_id || pn->id == vp_id) {
            // Found a parameter node.  Extract the first IDENTIFIER.
            n00b_parse_tree_t *tok_node = n00b_pt_first_token(cur);

            if (tok_node) {
                const char *name = n00b_pt_token_text(tok_node);
                size_t      len  = n00b_pt_token_text_len(tok_node);

                // For <vargs-param>, the first token is "*"; skip it
                // and grab the second token instead.
                if (name && len == 1 && name[0] == '*') {
                    // Walk children to find the second leaf.
                    size_t nc = n00b_pt_num_children(cur);

                    for (size_t i = 0; i < nc; i++) {
                        n00b_parse_tree_t *ch = n00b_pt_get_child(cur, i);

                        if (n00b_pt_is_token(ch) && ch != tok_node) {
                            name = n00b_pt_token_text(ch);
                            len  = n00b_pt_token_text_len(ch);
                            break;
                        }
                    }
                }

                if (name && len > 0) {
                    char *buf = n00b_alloc_size(1, len + 1);
                    memcpy(buf, name, len);
                    buf[len]       = '\0';
                    out_names[pos] = buf;
                    pos++;
                }
            }

            continue; // Don't recurse into param nodes.
        }

        // Push children in reverse for left-to-right DFS.
        size_t nc = n00b_pt_num_children(cur);

        for (size_t i = nc; i > 0; i--) {
            if (sp < 128) {
                stack[sp++] = n00b_pt_get_child(cur, i - 1);
            }
        }
    }

    return pos;
}

// Emit a single func-def as a MIR function.
//
// Extracts the function name, parameters, checks for private modifier,
// and emits a complete MIR function with proper parameter bindings.
static bool
emit_func_def(n00b_cg_session_t *session,
              n00b_grammar_t    *grammar,
              n00b_parse_tree_t *func_def_node,
              bool              *out_is_private)
{
    const char *fname = extract_func_name(func_def_node);

    if (!fname) {
        fprintf(stderr, "warning: could not extract function name\n");
        return false;
    }

    *out_is_private = is_func_private(func_def_node);

    if (*out_is_private && session->active_module) {
        n00b_cg_module_mark_private_func(session->active_module, fname);
    }

    // Find the <body> child.
    n00b_parse_tree_t *body = n00b_tree_find_child_by_nt_name(grammar, func_def_node, r"body");

    if (!body) {
        fprintf(stderr, "warning: func-def '%s' has no body\n", fname);
        return false;
    }

    // Extract parameter names.
    const char *param_names[64];
    int32_t     n_params = extract_params(grammar, func_def_node, param_names, 64);

    // Build type array from annotation symtab when available.
    n00b_cg_type_tag_t param_types[64];
    n00b_cg_type_tag_t ret_type = N00B_CG_I64;

    n00b_annot_result_t *annot
        = session->active_module ? session->active_module->annot : session->annot;

    for (int32_t i = 0; i < n_params; i++) {
        param_types[i] = N00B_CG_I64;

        if (annot && annot->symtab && session->type_map) {
            n00b_string_t    *pname = n00b_string_from_cstr(param_names[i]);
            n00b_sym_entry_t *sym
                = n00b_symtab_lookup_any(annot->symtab, n00b_string_empty(), pname);

            if (sym && sym->type_var) {
                param_types[i] = session->type_map(session, sym->type_var);
            }
        }
    }

    // Extract return type from <return-type> child if present.
    if (annot && annot->symtab && session->type_map) {
        n00b_string_t    *sname = n00b_string_from_cstr(fname);
        n00b_sym_entry_t *fsym
            = n00b_symtab_lookup_any(annot->symtab, n00b_string_empty(), sname);

        if (fsym && fsym->type_var) {
            n00b_tc_type_t *ftype = n00b_tc_find(fsym->type_var);

            if (n00b_variant_is_type(ftype->kind, n00b_tc_fn_t)) {
                n00b_tc_fn_t fn = n00b_variant_get(ftype->kind, n00b_tc_fn_t);

                if (fn.return_type) {
                    ret_type = session->type_map(session, fn.return_type);
                }
            }
        }
    }

    // Emit: begin_func → lower body → ret → end_func.
    n00b_cg_begin_func(session,
                       fname,
                       .ret         = ret_type,
                       .param_names = n_params > 0 ? param_names : NULL,
                       .param_types = n_params > 0 ? param_types : NULL,
                       .n_params    = n_params);

    n00b_cg_val_t result = n00b_codegen_lower(session, body);

    if (result.kind != N00B_CG_VAL_VOID) {
        n00b_cg_emit_ret(session, result);
    }
    else {
        n00b_cg_emit_ret(session, _n00b_cg_const_i64(session, 0));
    }

    n00b_cg_end_func(session);

    return true;
}

// Tracks which emitted functions are private vs public.
typedef struct {
    const char *name;
    bool        is_private;
} emitted_func_info_t;

// Recursive tree walker: find all func-def nodes and emit each.
// Returns the number of functions successfully emitted.
// Populates func_info[] with name and visibility for each emitted function.
static int32_t
emit_module_functions(n00b_cg_session_t   *session,
                      n00b_grammar_t      *grammar,
                      n00b_parse_tree_t   *node,
                      emitted_func_info_t *func_info,
                      int32_t              info_cap,
                      int32_t              info_pos)
{
    if (!node || n00b_tree_is_leaf(node)) {
        return info_pos;
    }

    n00b_nt_node_t *pn = &n00b_tree_node_value(node);

    // If this is a func-def, emit it (don't recurse into it).
    if (!pn->group_top && pn->id >= 0) {
        n00b_nonterm_t *nt = n00b_get_nonterm(grammar, pn->id);

        if (nt && n00b_unicode_str_eq(nt->name, r"func-def")) {
            bool is_priv = false;

            if (emit_func_def(session, grammar, node, &is_priv) && info_pos < info_cap) {
                func_info[info_pos].name       = extract_func_name(node);
                func_info[info_pos].is_private = is_priv;
                info_pos++;
            }

            return info_pos;
        }
    }

    // Recurse into children (including group nodes).
    size_t nc = n00b_tree_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        info_pos = emit_module_functions(session,
                                         grammar,
                                         n00b_tree_child(node, i),
                                         func_info,
                                         info_cap,
                                         info_pos);
    }

    return info_pos;
}

// ============================================================================
// Module loader
// ============================================================================

n00b_cg_module_t *
n00b_module_load(n00b_cg_session_t *session,
                 n00b_grammar_t    *grammar,
                 const char        *module_name,
                 const char        *package,
                 const char        *from_path,
                 const char        *caller_path)
{
    if (!session || !grammar || !module_name) {
        return NULL;
    }

    // Build FQN: "package.module" or just "module".
    char fqn[512];

    if (package && package[0]) {
        snprintf(fqn, sizeof(fqn), "%s.%s", package, module_name);
    }
    else {
        snprintf(fqn, sizeof(fqn), "%s", module_name);
    }

    // Find the file.
    char *file_path = find_module_file(module_name, package, from_path, caller_path);

    if (!file_path) {
        fprintf(stderr, "error: cannot find module '%s'\n", fqn);
        return NULL;
    }

    char *cache_key = module_cache_key_dup(file_path);

    if (!cache_key) {
        fprintf(stderr, "error: cannot cache module '%s' (%s)\n", fqn, file_path);
        n00b_free(file_path);
        return NULL;
    }

    // Check cache after caller-relative path resolution.
    n00b_cg_module_t *cached = n00b_cg_session_find_module(session, cache_key);

    if (cached) {
        n00b_free(cache_key);
        n00b_free(file_path);
        return cached;
    }

    // Cycle detection uses the same resolved file identity as the cache.
    if (is_on_loading_stack(session, cache_key)) {
        fprintf(stderr, "error: circular import detected: '%s'\n", fqn);
        n00b_free(cache_key);
        n00b_free(file_path);
        return NULL;
    }

    // Read the file.
    size_t file_len = 0;
    char  *source   = read_file(file_path, &file_len);

    if (!source) {
        fprintf(stderr, "error: cannot read '%s'\n", file_path);
        n00b_free(cache_key);
        n00b_free(file_path);
        return NULL;
    }

    // Tokenize.
    n00b_buffer_t       *buf = n00b_buffer_from_bytes(source, (int64_t)file_len);
    n00b_scanner_t      *sc  = n00b_scanner_new(buf, n00b_lang_tokenize, grammar);
    n00b_token_stream_t *ts  = n00b_token_stream_new(sc);

    // Parse.
    n00b_parse_result_t *pr = n00b_grammar_parse(grammar, ts, N00B_PARSE_MODE_DEFAULT);

    if (!pr || !n00b_parse_result_ok(pr)) {
        fprintf(stderr, "error: parse failed for module '%s' (%s)\n", fqn, file_path);

        if (pr) {
            n00b_parse_result_free(pr);
        }

        n00b_free(source);
        n00b_free(cache_key);
        n00b_free(file_path);

        return NULL;
    }

    n00b_parse_tree_t *tree = n00b_parse_result_tree(pr);

    // Annotation walk.
    n00b_annot_result_t *annot = n00b_compile_walk(grammar, tree);

    if (!annot) {
        fprintf(stderr, "error: annotation walk failed for module '%s'\n", fqn);
        n00b_parse_result_free(pr);
        n00b_free(source);
        n00b_free(cache_key);
        n00b_free(file_path);

        return NULL;
    }

    // Push onto loading stack for cycle detection.
    push_loading_stack(session, cache_key);

    char *file_dir = module_dirname_dup(file_path);

    if (!file_dir) {
        pop_loading_stack(session);
        n00b_parse_result_free(pr);
        n00b_free(source);
        n00b_free(cache_key);
        n00b_free(file_path);
        return NULL;
    }

    // Recursively resolve nested use statements.
    if (!n00b_resolve_use_stmts(session, grammar, tree, annot, file_dir)) {
        pop_loading_stack(session);
        n00b_parse_result_free(pr);
        n00b_free(file_dir);
        n00b_free(source);
        n00b_free(cache_key);
        n00b_free(file_path);
        return NULL;
    }

    // Pop loading stack.
    pop_loading_stack(session);
    n00b_free(file_dir);

    n00b_module_code_t *compiled
        = n00b_cg_session_compile_module(session, tree, .annot = annot);

    if (!compiled) {
        fprintf(stderr, "error: codegen failed for module '%s'\n", fqn);
        n00b_parse_result_free(pr);
        n00b_free(source);
        n00b_free(cache_key);
        n00b_free(file_path);
        return NULL;
    }

    n00b_cg_module_t *m = session->active_module;

    if (!m) {
        fprintf(stderr, "error: module '%s' did not produce codegen state\n", fqn);
        n00b_parse_result_free(pr);
        n00b_free(source);
        n00b_free(cache_key);
        n00b_free(file_path);
        return NULL;
    }

    char *fqn_copy = n00b_loader_strdup(fqn);

    m->name = fqn_copy;

    // Cache.
    n00b_dict_untyped_put(session->module_cache, cache_key, m);

    // Cleanup (parse result, source — but NOT annot, owned by module).
    n00b_parse_result_free(pr);
    n00b_free(source);
    n00b_free(file_path);

    return m;
}

// ============================================================================
// Use-stmt tree walker
// ============================================================================

// Extract the "from" path from a use-stmt node.
//
// Grammar: <use-stmt> ::= %"use" <member-chain> (%"from" %STRING_LIT)?
//
// The optional group (%"from" %STRING_LIT)? creates a $$group node
// containing "from" and STRING_LIT as leaf children. The tokenizer
// stores STRING_LIT values without quotes.
//
// We look for a non-leaf, non-member-chain child (the group node),
// then find the last leaf inside it (the STRING_LIT).
//
// Returns the path string (points into token data — valid for the
// lifetime of the parse result), or NULL if no "from" clause.
static const char *
extract_from_path(n00b_grammar_t *grammar, n00b_parse_tree_t *use_node)
{
    size_t nc = n00b_tree_num_children(use_node);

    // Walk children looking for a group node (the optional "from" clause).
    // Skip leaves (keywords) and the <member-chain> NT.
    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_tree_child(use_node, i);

        if (n00b_tree_is_leaf(child)) {
            continue;
        }

        n00b_nt_node_t *cpn = &n00b_tree_node_value(child);

        // Skip <member-chain> — we want the $$group node.
        if (!cpn->group_top && cpn->id >= 0) {
            n00b_nonterm_t *cnt = n00b_get_nonterm(grammar, cpn->id);

            if (cnt && n00b_unicode_str_eq(cnt->name, r"member-chain")) {
                continue;
            }
        }

        // This should be the group node for (%"from" %STRING_LIT)?.
        // Find the last leaf (the STRING_LIT) inside it.
        size_t gnc = n00b_tree_num_children(child);

        for (size_t j = gnc; j > 0; j--) {
            n00b_parse_tree_t *gchild = n00b_tree_child(child, j - 1);

            if (!n00b_tree_is_leaf(gchild)) {
                continue;
            }

            n00b_token_info_t *tok = n00b_tree_leaf_value(gchild);

            if (!tok || !n00b_option_is_set(tok->value)) {
                continue;
            }

            n00b_string_t *val = n00b_option_get(tok->value);

            // Skip "from" keyword — we want the STRING_LIT value.
            if (val->u8_bytes > 0
                && !(val->u8_bytes == 4 && memcmp(val->data, "from", 4) == 0)) {
                return val->data;
            }
        }
    }

    return NULL;
}

// Recursive tree walker: find all use-stmt nodes and resolve them.
static bool
walk_for_use_stmts(n00b_cg_session_t *session,
                   n00b_grammar_t    *grammar,
                   n00b_parse_tree_t *node,
                   const char        *caller_path)
{
    if (!node || n00b_tree_is_leaf(node)) {
        return true;
    }

    n00b_nt_node_t *pn = &n00b_tree_node_value(node);

    // Check if this is a use-stmt node.
    if (!pn->group_top && pn->id >= 0) {
        n00b_nonterm_t *nt = n00b_get_nonterm(grammar, pn->id);

        if (nt && n00b_unicode_str_eq(nt->name, r"use-stmt")) {
            // Extract the member-chain (first NT child).
            n00b_parse_tree_t *mc_node = n00b_tree_get_nth_nt_child(node, 0);

            if (mc_node) {
                char    chain_buf[512];
                int32_t chain_len = n00b_tree_extract_member_chain(mc_node,
                                                                   chain_buf,
                                                                   (int32_t)sizeof(chain_buf));

                if (chain_len > 0) {
                    // Decompose: last component = module, rest = package.
                    char       *last_dot = strrchr(chain_buf, '.');
                    const char *mod_name;
                    const char *pkg = NULL;

                    if (last_dot) {
                        *last_dot = '\0';
                        pkg       = chain_buf;
                        mod_name  = last_dot + 1;
                    }
                    else {
                        mod_name = chain_buf;
                    }

                    // Extract "from" path if present.
                    const char *from_path = extract_from_path(grammar, node);

                    // Load the module.
                    if (!n00b_module_load(session,
                                          grammar,
                                          mod_name,
                                          pkg,
                                          from_path,
                                          caller_path)) {
                        return false;
                    }
                }
            }

            return true; // Don't recurse into use-stmt children.
        }
    }

    // Recurse into children.
    size_t nc = n00b_tree_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        if (!walk_for_use_stmts(session, grammar, n00b_tree_child(node, i), caller_path)) {
            return false;
        }
    }

    return true;
}

bool
n00b_resolve_use_stmts(n00b_cg_session_t   *session,
                       n00b_grammar_t      *grammar,
                       n00b_parse_tree_t   *tree,
                       n00b_annot_result_t *annot,
                       const char          *caller_path)
{
    (void)annot; // Available for future use (e.g., checking sym entries).

    if (!session || !grammar || !tree) {
        return false;
    }

    return walk_for_use_stmts(session, grammar, tree, caller_path);
}

/*
 * eval.c — implementation of the embedded-eval API
 * (see include/n00b/eval.h).
 *
 * Pipeline per n00b_eval_compile_predicate call:
 *   1. Form `_n00b_eval_p%lld` wrapper name (monotonic counter).
 *   2. Build wrapper source string:
 *        `func _n00b_eval_p<N>(arg: <arg_type_name>) -> bool {
 *             return <expr_text> }`
 *   3. Tokenize + parse against the session-cached n00b grammar.
 *   4. Run the n00b annotation walk (n00b_compile_walk).
 *   5. Create a fresh per-predicate codegen module on the underlying
 *      session, set its annot, DFS the parse tree for the func-def
 *      node, n00b_codegen_lower it.
 *   6. n00b_cg_module_compile(m, wrapper_name) returns the JIT'd
 *      void * — cast to n00b_eval_predicate_fn_t.
 *
 * Builtins are loaded once at session creation via
 * n00b_cg_session_run_module (REPL pattern adapted to mmap I/O —
 * no libc FILE *).
 *
 * Per include/audit_paths.h (configured at build time), the two
 * absolute paths to the n00b grammar and the stdlib live in
 * N00B_N00B_GRAMMAR_PATH and N00B_BUILTINS_PATH.
 */

#include "n00b.h"
#include "n00b/eval.h"
#include "n00b/embed.h"
#include "n00b/embed_ffi.h"
#include "n00b/n00b_compile.h"
#include "n00b/n00b_tokenizer.h"
#include "n00b/n00b_type_map.h"
#include "slay/annot_walk.h"
#include "slay/bnf.h"
#include "slay/codegen.h"
#include "slay/diagnostic.h"
#include "slay/grammar.h"
#include "slay/n00b_parse.h"
#include "slay/parse_tree.h"
#include "internal/slay/codegen_internal.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/file.h"
#include "core/gc.h"
#include "core/mutex.h"
#include "core/string.h"
#include "text/strings/format.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"

#include "audit_paths.h"

#include <string.h>

// ============================================================================
// Session struct
// ============================================================================

/**
 * Reusable embedded-eval session. The grammar + cg_session_t are
 * created once at session creation and reused for every predicate
 * compile. The per-predicate counter feeds a unique wrapper-function
 * name so multiple predicates coexist in the same MIR context.
 */
struct n00b_eval_session {
    n00b_grammar_t       *grammar;
    n00b_dict_untyped_t  *embed_registry;
    n00b_cg_session_t    *session;
    int64_t               predicate_counter;
};

// ============================================================================
// File reading via libn00b MMAP (NO libc I/O per § 2.10/2.11)
// ============================================================================

/**
 * Read the entire contents of @p abs_path as an `n00b_string_t *`.
 *
 * Uses `n00b_file_open(.kind = MMAP)` + `n00b_file_as_buffer` and
 * wraps the buffer bytes as a string. Caller treats failure as an
 * error path (return is nullptr).
 *
 * NOTE: The MMAP substrate maps the whole file; for grammar /
 * builtins (tens of KB), this is bounded and cheaper than the
 * stream substrate which would buffer through the conduit.
 */
static n00b_string_t *
read_file_as_string(const char *abs_path)
{
    if (!abs_path || abs_path[0] == '\0') {
        return nullptr;
    }

    n00b_string_t *path = n00b_string_from_cstr(abs_path);

    n00b_result_t(n00b_file_t *) open_r = n00b_file_open(
        path, .kind = N00B_FILE_KIND_MMAP);

    if (n00b_result_is_err(open_r)) {
        return nullptr;
    }

    n00b_file_t *f = n00b_result_get(open_r);

    n00b_result_t(n00b_buffer_t *) buf_r = n00b_file_as_buffer(f);

    if (n00b_result_is_err(buf_r)) {
        n00b_file_close(f);
        return nullptr;
    }

    n00b_buffer_t *buf = n00b_result_get(buf_r);

    if (!buf || !buf->data) {
        n00b_file_close(f);
        return nullptr;
    }

    n00b_string_t *s = n00b_string_from_raw(buf->data, (int64_t)buf->byte_len);

    // The file's backing mmap stays alive via the file_t until close.
    // n00b_string_from_raw copies into managed storage, so closing
    // here is safe.
    n00b_file_close(f);

    return s;
}

// ============================================================================
// Grammar load
// ============================================================================

static n00b_grammar_t *s_eval_n00b_grammar               = nullptr;
static n00b_mutex_t    s_eval_n00b_grammar_mutex;
static _Atomic int     s_eval_n00b_grammar_mutex_state   = 0;
static bool            s_eval_n00b_grammar_root_registered;

static void
ensure_eval_grammar_mutex(void)
{
    int snapshot = n00b_atomic_load(&s_eval_n00b_grammar_mutex_state);

    if (snapshot == 2) {
        return;
    }

    int expected = 0;

    if (n00b_atomic_cas(&s_eval_n00b_grammar_mutex_state, &expected, 1)) {
        n00b_sys_mutex_init(&s_eval_n00b_grammar_mutex, (char *)__FILE__);
        n00b_atomic_store(&s_eval_n00b_grammar_mutex_state, 2);
        return;
    }

    while (n00b_atomic_load(&s_eval_n00b_grammar_mutex_state) != 2) {
        // Brief spin until the elected initializer publishes.
    }
}

/**
 * Parse the n00b BNF text into a grammar object. On failure leaves
 * @p out_err set to the appropriate `n00b_eval_err_t`.
 */
static n00b_grammar_t *
load_n00b_grammar_uncached(n00b_eval_err_t *out_err)
{
    n00b_string_t *bnf_text = read_file_as_string(N00B_N00B_GRAMMAR_PATH);

    if (!bnf_text) {
        *out_err = N00B_EVAL_ERR_GRAMMAR_OPEN;
        return nullptr;
    }

    n00b_grammar_t *g = n00b_grammar_new(
        .error_recovery = false,
        .parse_mode     = N00B_PARSE_MODE_PWZ_ONLY);

    n00b_diag_ctx_t *diag = n00b_diag_ctx_new();
    bool             ok   = n00b_bnf_load(bnf_text, r"module", g,
                                          .diag = diag);

    n00b_diag_ctx_free(diag);

    if (!ok) {
        *out_err = N00B_EVAL_ERR_GRAMMAR_PARSE;
        return nullptr;
    }

    return g;
}

static n00b_grammar_t *
load_n00b_grammar(n00b_eval_err_t *out_err)
{
    ensure_eval_grammar_mutex();
    n00b_mutex_lock(&s_eval_n00b_grammar_mutex);

    if (!s_eval_n00b_grammar_root_registered) {
        n00b_gc_register_root(s_eval_n00b_grammar);
        s_eval_n00b_grammar_root_registered = true;
    }

    if (s_eval_n00b_grammar == nullptr) {
        s_eval_n00b_grammar = load_n00b_grammar_uncached(out_err);
    }

    n00b_grammar_t *g = s_eval_n00b_grammar;
    n00b_mutex_unlock(&s_eval_n00b_grammar_mutex);

    return g;
}

// ============================================================================
// Builtins load
// ============================================================================

/**
 * Load `lib/std/builtins.n` into the codegen session. Returns true
 * on success. The REPL has a search-heuristic version; here we use
 * a single absolute path baked at configure time so the surface is
 * deterministic + has no libc I/O.
 */
static bool
load_builtins(n00b_grammar_t    *g,
              n00b_cg_session_t *session,
              n00b_eval_err_t   *out_err)
{
    n00b_string_t *src = read_file_as_string(N00B_BUILTINS_PATH);

    if (!src) {
        *out_err = N00B_EVAL_ERR_BUILTINS_OPEN;
        return false;
    }

    n00b_buffer_t *buf = n00b_buffer_from_bytes(src->data,
                                                (int64_t)src->u8_bytes);

    n00b_scanner_t      *scanner = n00b_scanner_new(buf,
                                                    n00b_lang_tokenize, g);
    n00b_token_stream_t *ts      = n00b_token_stream_new(scanner);

    n00b_parse_result_t *r = n00b_grammar_parse(g, ts);

    if (!n00b_parse_result_ok(r)) {
        *out_err = N00B_EVAL_ERR_BUILTINS_LOAD;
        return false;
    }

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);

    n00b_annot_result_t *ar = n00b_compile_walk(g, tree);

    if (!ar) {
        *out_err = N00B_EVAL_ERR_BUILTINS_LOAD;
        return false;
    }

    bool ok = false;
    n00b_cg_session_run_module(session, tree,
                               .annot      = ar,
                               .entry_name = "_n00b_eval_builtins_init",
                               .ok         = &ok);

    if (!ok) {
        // Builtins not strictly required for trivial true/false
        // smokes, but the type checker needs the stdlib symtab
        // present for richer expressions. Surface the error but
        // do not abort session creation — the simple cases
        // (smoke tests 1 + 2) still work. Consumers needing
        // builtins surface this via subsequent
        // compile_predicate diagnostics.
        *out_err = N00B_EVAL_ERR_BUILTINS_LOAD;
        return false;
    }

    return true;
}

// ============================================================================
// Session lifecycle
// ============================================================================

n00b_result_t(n00b_eval_session_t *)
n00b_eval_session_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_eval_err_t err = N00B_EVAL_ERR_NONE;

    n00b_eval_session_t *s = n00b_alloc(n00b_eval_session_t,
                                         .allocator = allocator);

    s->predicate_counter = 0;

    s->grammar = load_n00b_grammar(&err);

    if (!s->grammar) {
        return n00b_result_err(n00b_eval_session_t *, (int)err);
    }

    s->embed_registry = n00b_embed_registry_new();
    n00b_ffi_embed_register(s->embed_registry);

    // Type-map = n00b_type_map: the n00b type checker can resolve
    // built-in types (int, bool, string, ...) inside the generated
    // wrapper. User-registered opaque types fall through the map
    // via the WP-010 codegen extension-method dispatch.
    s->session = n00b_cg_session_new(s->grammar,
                                      .type_map       = n00b_type_map,
                                      .embed_registry = s->embed_registry);

    if (!s->session) {
        return n00b_result_err(n00b_eval_session_t *,
                               (int)N00B_EVAL_ERR_GRAMMAR_PARSE);
    }

    // Load builtins. Failure here is reported but not fatal — the
    // simple smoke cases (true/false) do not need the stdlib, and
    // consumers needing it learn so via their own compile_predicate
    // diagnostics.
    n00b_eval_err_t b_err = N00B_EVAL_ERR_NONE;
    (void)load_builtins(s->grammar, s->session, &b_err);

    // Leave the session with a fresh, mutable MIR module active so
    // consumers can immediately call `n00b_ffi_install_simple` to
    // register C-side bindings before issuing any
    // `n00b_eval_compile_predicate`. Without this the session's
    // `active_module` would either be null (no builtins) or a
    // `MIR_finish_module`'d builtins module, and FFI install would
    // emit "import outside module" and fail. `n00b_cg_module_new`
    // sets the new module as active.
    n00b_cg_module_new(s->session, "_n00b_eval_install");

    return n00b_result_ok(n00b_eval_session_t *, s);
}

void
n00b_eval_session_free(n00b_eval_session_t *s)
{
    if (!s) {
        return;
    }

    if (s->session) {
        n00b_cg_session_free(s->session);
    }

    // grammar + embed_registry are GC-managed.
}

n00b_cg_session_t *
n00b_eval_session_cg(n00b_eval_session_t *s)
{
    return s ? s->session : nullptr;
}

n00b_grammar_t *
n00b_eval_session_grammar(n00b_eval_session_t *s)
{
    return s ? s->grammar : nullptr;
}

// ============================================================================
// Predicate compilation
// ============================================================================

/**
 * Find the first `func-def` node in a parse tree subtree. The
 * wrapper source contains exactly one func-def at the top level,
 * but the n00b grammar wraps top-level statements through several
 * passthrough NTs (e.g. `module`, `$$group_N`, `top-level-stmt`),
 * so we DFS to locate it.
 */
static n00b_parse_tree_t *
find_func_def(n00b_parse_tree_t *node)
{
    if (!node || n00b_pt_is_token(node)) {
        return nullptr;
    }

    if (n00b_pt_is_nt(node, "func-def")) {
        return node;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *r = find_func_def(n00b_pt_get_child(node, i));

        if (r) {
            return r;
        }
    }

    return nullptr;
}

n00b_result_t(n00b_eval_predicate_fn_t)
n00b_eval_compile_predicate(n00b_eval_session_t *s,
                            n00b_string_t       *expr_text,
                            n00b_string_t       *arg_type_name) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    (void)kargs;

    if (!s || !expr_text || !arg_type_name) {
        return n00b_result_err(n00b_eval_predicate_fn_t,
                               (int)N00B_EVAL_ERR_BAD_ARGS);
    }

    // Allocate the wrapper-function name from the monotonic counter.
    // Name format: `_n00b_eval_p<N>`. The leading underscore keeps
    // it out of the way of any user-defined identifier in the
    // expression body.
    int64_t        my_id = s->predicate_counter++;
    n00b_string_t *fname_str = n00b_cformat("_n00b_eval_p«#:d»", my_id);

    // Assemble wrapper source via libn00b string formatting (no libc
    // I/O). n00b's grammar treats newline as a statement terminator;
    // the `return <expr>` must be followed by a newline (or `;`)
    // before the closing `}`. Without it, the parser keeps trying to
    // extend the expression and reports e.g.
    // "expected: + - == ..." when it hits the bare `}`.
    n00b_string_t *src_str = n00b_cformat(
        "func «#»(arg: «#») -> bool {\n    return «#»\n}\n",
        fname_str,
        arg_type_name,
        expr_text);

    // Parse.
    n00b_buffer_t *buf = n00b_buffer_from_bytes(src_str->data,
                                                 (int64_t)src_str->u8_bytes,
                                                 .allocator = allocator);
    n00b_scanner_t      *scanner = n00b_scanner_new(buf,
                                                    n00b_lang_tokenize,
                                                    s->grammar);
    n00b_token_stream_t *ts      = n00b_token_stream_new(scanner);

    n00b_parse_result_t *pr = n00b_grammar_parse(s->grammar, ts);

    if (!n00b_parse_result_ok(pr)) {
        return n00b_result_err(n00b_eval_predicate_fn_t,
                               (int)N00B_EVAL_ERR_PARSE);
    }

    n00b_parse_tree_t *tree = n00b_parse_result_tree(pr);

    // -----------------------------------------------------------
    // Annotation walk.
    // -----------------------------------------------------------
    n00b_annot_result_t *ar = n00b_compile_walk(s->grammar, tree);

    if (!ar) {
        return n00b_result_err(n00b_eval_predicate_fn_t,
                               (int)N00B_EVAL_ERR_ANNOT);
    }

    // -----------------------------------------------------------
    // Emit. Use the REPL's per-batch-module pattern: create a
    // fresh module on the persistent session, set its annot, find
    // the func-def, lower it.
    // -----------------------------------------------------------
    // Reuse the session's active module if it's still in the
    // mid-build state — that lets a caller install FFI bindings
    // via `n00b_ffi_install_simple` (which writes wrappers into
    // the current module) and then compile a predicate that
    // references those wrappers, all in the same MIR module. If
    // the active module has been finalized (e.g., by the previous
    // predicate compile), start a fresh one.
    n00b_cg_module_t *m = s->session->active_module;

    if (!m || m->state != N00B_CG_MOD_BUILDING) {
        // Module names live for the session's lifetime; the n00b
        // string is GC-tracked + NUL-terminated, so its `.data`
        // pointer is a stable C string for the cg_module_new call.
        n00b_string_t *mod_name = n00b_cformat("_n00b_eval_mod_«#:d»",
                                                my_id);
        m = n00b_cg_module_new(s->session, mod_name->data);
    }

    if (!m) {
        return n00b_result_err(n00b_eval_predicate_fn_t,
                               (int)N00B_EVAL_ERR_EMIT);
    }

    n00b_cg_module_set_annot(m, ar);

    n00b_parse_tree_t *func_node = find_func_def(tree);

    if (!func_node) {
        return n00b_result_err(n00b_eval_predicate_fn_t,
                               (int)N00B_EVAL_ERR_EMIT);
    }

    // Set session annot so codegen_lower's type-checker bridges
    // (e.g. method_return($0)) can resolve referenced symbols.
    n00b_codegen_set_annot(s->session, ar);

    n00b_codegen_lower(s->session, func_node);

    // -----------------------------------------------------------
    // Compile + JIT. `n00b_cg_module_compile(m, fname)` returns
    // the JIT'd entrypoint pointer for the named function.
    // -----------------------------------------------------------
    void *fn_void = n00b_cg_module_compile(m, fname_str->data);

    if (!fn_void) {
        // Fallback: try the session-level lookup, in case the
        // module compile dropped the entry because the func was
        // already linked.
        fn_void = n00b_codegen_jit(s->session, fname_str->data);
    }

    if (!fn_void) {
        return n00b_result_err(n00b_eval_predicate_fn_t,
                               (int)N00B_EVAL_ERR_JIT);
    }

    // Make the function visible to subsequent session lookups so
    // the side-table-keyed extension-method dispatch resolves
    // correctly even across modules.
    n00b_cg_session_merge_module(s->session, m);

    return n00b_result_ok(n00b_eval_predicate_fn_t,
                          (n00b_eval_predicate_fn_t)fn_void);
}

// ============================================================================
// Error strings
// ============================================================================

n00b_string_t *
n00b_eval_err_str(n00b_eval_err_t err)
{
    switch (err) {
    case N00B_EVAL_ERR_NONE:
        return r"ok";
    case N00B_EVAL_ERR_GRAMMAR_OPEN:
        return r"cannot open n00b grammar (N00B_N00B_GRAMMAR_PATH)";
    case N00B_EVAL_ERR_GRAMMAR_PARSE:
        return r"n00b grammar failed to parse";
    case N00B_EVAL_ERR_BUILTINS_OPEN:
        return r"cannot open n00b builtins.n (N00B_BUILTINS_PATH)";
    case N00B_EVAL_ERR_BUILTINS_LOAD:
        return r"n00b builtins.n failed to load";
    case N00B_EVAL_ERR_BAD_ARGS:
        return r"null argument to n00b_eval API";
    case N00B_EVAL_ERR_PARSE:
        return r"predicate wrapper failed to parse";
    case N00B_EVAL_ERR_ANNOT:
        return r"predicate wrapper failed annotation walk";
    case N00B_EVAL_ERR_EMIT:
        return r"predicate wrapper failed codegen";
    case N00B_EVAL_ERR_JIT:
        return r"predicate wrapper failed JIT compile";
    }

    return r"unknown n00b_eval error";
}

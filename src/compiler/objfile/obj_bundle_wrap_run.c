// WP-017 wrap runtime: run an EMBEDDED_N00B policy program with the bundle's
// embedded objects mounted as a VFS the program reads.
//
// Phase 2 (this file, so far): `_n00b_obj_bundle_vfs_from_bundle` builds an
// in-memory VFS from the bundle's artifacts — the "filesystem inside an object
// file" the policy program controls. It reaches the bundle's private artifact
// records only through the indexed enumeration seam in
// internal/compiler/objfile/obj_bundle_exec.h (defined in obj_bundle.c), never by
// dereferencing the file-private artifact struct.
//
// Later phases add `_n00b_obj_bundle_run_wrapped` (compile + run the EMBEDDED_N00B
// program against this VFS) and the policy-payload accessor. This translation unit
// makes NO change to exec_run, the predicate evaluator, the policy-kind support
// gates, or the expression-start check.

#include "n00b.h"
#include "adt/array.h"
#include "adt/result.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"
#include "text/strings/string_ops.h"
#include "vfs/vfs.h"
#include "vfs/backend_memory.h"
#include "vfs/types.h"
#include "n00b/eval.h"
#include "n00b/embed_ffi.h"
#include "n00b/n00b_compile.h"
#include "n00b/n00b_tokenizer.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "slay/codegen.h"
#include "slay/n00b_parse.h"
#include "util/wrap_policy.h"
#include "compiler/objfile/obj_bundle.h"
#include "internal/compiler/objfile/obj_bundle_exec.h"

// The wrap policy FFI shims are resolved by NAME (dlsym) at install time, so
// nothing references them at C link time. In a statically-linked executable that
// would let the linker drop their archive member (src/util/wrap_policy.c) and the
// dlsym install would then fail at runtime. This `used` keep-alive forces the
// member to be linked (and, with -rdynamic, exported for dlsym). The exec-target
// shim needs no such anchor: run_wrapped calls _n00b_obj_bundle_wrap_ctx_set in
// its own TU, which already pulls obj_bundle_wrap_ffi.c.
[[gnu::used]] static void *const n00b_wrap_policy_ffi_keepalive[] = {
    (void *)n00b_caller_is_blocked_agent,
    (void *)n00b_policy_eprint_shim,
};

// mkdir one directory, tolerating "already exists" (shared parents + the root are
// created repeatedly across artifacts). Returns false only on a real failure.
static bool
_vfs_mkdir_tolerant(n00b_vfs_t *vfs, n00b_string_t *dir)
{
    auto r = n00b_vfs_mkdir(vfs, dir);

    if (n00b_result_is_ok(r)) {
        return true;
    }

    return n00b_result_get_err(r) == N00B_VFS_ERR_EXISTS;
}

// Create every ANCESTOR directory of @p vpath (an absolute "/"-rooted path). The
// in-memory backend does NOT auto-create parents, so each intermediate component
// is mkdir'd in order. The leading '/' (index 0) is the root, created by the
// caller; this walks the interior separators.
static bool
_vfs_make_ancestor_dirs(n00b_vfs_t       *vfs,
                        n00b_string_t    *vpath,
                        n00b_allocator_t *allocator)
{
    const char *data = vpath->data;
    int64_t     len  = (int64_t)vpath->u8_bytes;

    for (int64_t i = 1; i < len; i++) {
        if (data[i] != '/') {
            continue;
        }

        // Logical paths are normalized ASCII-'/'-separated; slicing at a '/' is a
        // valid UTF-8 boundary.
        n00b_string_t *dir = n00b_string_from_raw(data, i, .allocator = allocator);

        if (!_vfs_mkdir_tolerant(vfs, dir)) {
            return false;
        }
    }

    return true;
}

n00b_result_t(n00b_vfs_t *)
_n00b_obj_bundle_vfs_from_bundle(n00b_obj_bundle_t *bundle) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    ensures {
        !result.is_ok || result.ok != nullptr;   // D-028
    }
{
    if (bundle == nullptr) {
        return n00b_result_err(n00b_vfs_t *,
                               N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);
    }

    auto vfs_result = n00b_vfs_new(.allocator = allocator);

    if (n00b_result_is_err(vfs_result)) {
        return n00b_result_err(n00b_vfs_t *, N00B_OBJ_BUNDLE_ERR_BUILD);
    }

    n00b_vfs_t *vfs = n00b_result_get(vfs_result);

    auto backend_result = n00b_vfs_backend_memory_new(.allocator = allocator);

    if (n00b_result_is_err(backend_result)) {
        n00b_vfs_destroy(vfs);
        return n00b_result_err(n00b_vfs_t *, N00B_OBJ_BUNDLE_ERR_BUILD);
    }

    n00b_vfs_backend_t *backend = n00b_result_get(backend_result);

    if (n00b_result_is_err(n00b_vfs_mount(vfs, r"/", backend, 0))) {
        n00b_vfs_destroy(vfs);
        return n00b_result_err(n00b_vfs_t *, N00B_OBJ_BUNDLE_ERR_BUILD);
    }

    // The in-memory backend has no implicit root; create it explicitly.
    if (!_vfs_mkdir_tolerant(vfs, r"/")) {
        n00b_vfs_destroy(vfs);
        return n00b_result_err(n00b_vfs_t *, N00B_OBJ_BUNDLE_ERR_BUILD);
    }

    int64_t count = _n00b_obj_bundle_artifact_count(bundle);

    for (int64_t i = 0; i < count; i++) {
        n00b_string_t *logical =
            _n00b_obj_bundle_artifact_logical_path_at(bundle, i);
        const n00b_buffer_t *payload =
            _n00b_obj_bundle_artifact_payload_at(bundle, i);

        // Absolute VFS path: "/" + the (relative, normalized) logical path.
        n00b_string_t *vpath =
            n00b_unicode_str_cat(r"/", logical, .allocator = allocator);

        if (!_vfs_make_ancestor_dirs(vfs, vpath, allocator)) {
            n00b_vfs_destroy(vfs);
            return n00b_result_err(n00b_vfs_t *, N00B_OBJ_BUNDLE_ERR_BUILD);
        }

        if (payload == nullptr) {
            // Directory-kind artifact: the node itself is a directory.
            if (!_vfs_mkdir_tolerant(vfs, vpath)) {
                n00b_vfs_destroy(vfs);
                return n00b_result_err(n00b_vfs_t *, N00B_OBJ_BUNDLE_ERR_BUILD);
            }
            continue;
        }

        auto open_result = n00b_vfs_open(vfs, vpath, N00B_VFS_O_W);

        if (n00b_result_is_err(open_result)) {
            n00b_vfs_destroy(vfs);
            return n00b_result_err(n00b_vfs_t *, N00B_OBJ_BUNDLE_ERR_BUILD);
        }

        n00b_vfs_fh_t fh = n00b_result_get(open_result);

        // n00b_vfs_write copies the bytes into the handle's pending write image,
        // so the borrowed (const) payload can be passed through; the const is
        // dropped only at this hand-off and the write does not mutate it (mirrors
        // obj_bundle_exec_run.c's NFS serve path).
        if (n00b_result_is_err(n00b_vfs_write(vfs, fh, (n00b_buffer_t *)payload))) {
            n00b_vfs_destroy(vfs);
            return n00b_result_err(n00b_vfs_t *, N00B_OBJ_BUNDLE_ERR_BUILD);
        }

        // close commits the pending write image; a close failure means the bytes
        // never landed, so it is a build failure, not a silent partial VFS.
        if (n00b_result_is_err(n00b_vfs_close(vfs, fh))) {
            n00b_vfs_destroy(vfs);
            return n00b_result_err(n00b_vfs_t *, N00B_OBJ_BUNDLE_ERR_BUILD);
        }
    }

    return n00b_result_ok(n00b_vfs_t *, vfs);
}

// ---------------------------------------------------------------------------
// Phase 3 (D-052): run the EMBEDDED_N00B policy as a full n00b PROGRAM.
//
// Separate path from exec_run / the predicate evaluator / the is_supported gates
// / has_expression_start — all UNTOUCHED. The program decides via FFI facts and,
// on allow, execs a chosen target via the `exec_target` FFI shim (which runs the
// wrap-context bundle through the WP-016 exec path). MVP = facts + exec; reading
// embedded file contents is DF-017-01 (deferred).
// ---------------------------------------------------------------------------
n00b_result_t(int64_t)
_n00b_obj_bundle_run_wrapped(n00b_obj_bundle_t *bundle) _kargs
{
    n00b_allocator_t              *allocator = nullptr;
    n00b_array_t(n00b_string_t *) *argv      = nullptr;
}
    // No `ensures`: result.ok is the policy program's int64 verdict, which is
    // unconstrained (any value is valid) — there is nothing to assert. @post
    // prose is binding (verdict carried in result.ok; a controller policy that
    // execs a target via the shim never returns).
{
    if (bundle == nullptr) {
        return n00b_result_err(int64_t, N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);
    }

    // 1. Read the EMBEDDED_N00B EXECUTION-scope policy SOURCE (parsed seam).
    n00b_string_t *source = _n00b_obj_bundle_embedded_policy_source_for_scope(
        bundle,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
        .allocator = allocator);

    if (source == nullptr) {
        return n00b_result_err(int64_t, N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);
    }

    // 2. Build the run session (loads builtins internally; NOT the tool-only
    //    n00b_load_builtins).
    auto sr = n00b_eval_session_new(.allocator = allocator);

    if (n00b_result_is_err(sr)) {
        return n00b_result_err(int64_t, N00B_OBJ_BUNDLE_ERR_BUILD);
    }

    n00b_eval_session_t *s  = n00b_result_get(sr);
    n00b_cg_session_t   *cg = n00b_eval_session_cg(s);

    // 3. Install the standard wrap policy FFI surface (D-052: facts + effects).
    //    `exec_target() -> i64` execs the chosen target; `caller_is_blocked_agent()
    //    -> i64` is the process-ancestry fact; `eprint(cstring) -> i64` writes a
    //    message to stderr (the n00b `print` builtin targets stdout only). These
    //    are generic policy primitives — any EMBEDDED_N00B program may use them;
    //    the agent-guard demo (Phase 4) uses all three.
    static const char *eprint_params[] = {"cstring"};

    if (!n00b_ffi_install_simple(cg,
                                 "exec_target",
                                 "n00b_wrap_exec_target_shim",
                                 nullptr,
                                 0,
                                 "i64")
        || !n00b_ffi_install_simple(cg,
                                    "caller_is_blocked_agent",
                                    "n00b_caller_is_blocked_agent",
                                    nullptr,
                                    0,
                                    "i64")
        || !n00b_ffi_install_simple(cg,
                                    "eprint",
                                    "n00b_policy_eprint_shim",
                                    eprint_params,
                                    1,
                                    "i64")) {
        n00b_eval_session_free(s);
        return n00b_result_err(int64_t, N00B_OBJ_BUNDLE_ERR_BUILD);
    }

    // 3b. Finalize the eval session's "install" module. n00b_eval_session_new
    //     leaves a fresh, unfinished MIR module active so consumers can install
    //     FFI bindings and then compile a predicate into the SAME module (the
    //     blessed eval pattern). We are running a full PROGRAM via run_module
    //     instead, which opens its own module — and MIR rejects opening a new
    //     module while one is unfinished. Compiling one throwaway predicate
    //     (the supported "install FFI then compile a predicate" path) finalizes
    //     + merges the install module (publishing the exec_target wrapper
    //     session-globally) so the subsequent run_module can proceed cleanly.
    auto seal = n00b_eval_compile_predicate(s, r"true", r"bool",
                                            .allocator = allocator);

    if (n00b_result_is_err(seal)) {
        n00b_eval_session_free(s);
        return n00b_result_err(int64_t, N00B_OBJ_BUNDLE_ERR_BUILD);
    }

    // 4. Set the runtime-global wrap context so the shims reach the bundle +
    //    the passthrough argv forwarded to the exec'd target.
    _n00b_obj_bundle_wrap_ctx_set(bundle, allocator, argv);

    // 5. Parse the policy source into a tree (n00b-source chain; n00b_lang_tokenize,
    //    NOT the C lexer).
    n00b_grammar_t *g   = n00b_eval_session_grammar(s);
    n00b_buffer_t  *buf =
        n00b_buffer_from_bytes(source->data, (int64_t)source->u8_bytes,
                               .allocator = allocator);
    n00b_scanner_t      *scanner = n00b_scanner_new(buf, n00b_lang_tokenize, g);
    n00b_token_stream_t *ts      = n00b_token_stream_new(scanner);
    n00b_parse_result_t *pr      = n00b_grammar_parse(g, ts);

    if (!n00b_parse_result_ok(pr)) {
        n00b_parse_result_free(pr);
        _n00b_obj_bundle_wrap_ctx_clear();
        n00b_eval_session_free(s);
        return n00b_result_err(int64_t, N00B_OBJ_BUNDLE_ERR_BUILD);
    }

    n00b_parse_tree_t   *tree = n00b_parse_result_tree(pr);
    n00b_annot_result_t *ar   = n00b_compile_walk(g, tree);

    if (ar == nullptr) {
        // Annotation walk failed (returns NULL on error) — distinct early return
        // (matches the module-loader pattern) rather than subsuming into the
        // generic run_module failure.
        n00b_parse_result_free(pr);
        _n00b_obj_bundle_wrap_ctx_clear();
        n00b_eval_session_free(s);
        return n00b_result_err(int64_t, N00B_OBJ_BUNDLE_ERR_BUILD);
    }

    // 6. Compile + run the module → int64 verdict. On the controller path the
    //    program calls exec_target() and never returns from run_module (the
    //    process is replaced); the session is reclaimed by the OS in that case.
    bool    ok      = false;
    int64_t verdict = n00b_cg_session_run_module(cg,
                                                 tree,
                                                 .annot = ar,
                                                 .ok    = &ok);

    // run_module is done with the tree; free the parse result (owns the tree),
    // matching the n00b.c run-path idiom (free after run_module).
    n00b_parse_result_free(pr);
    _n00b_obj_bundle_wrap_ctx_clear();
    n00b_eval_session_free(s);

    if (!ok) {
        return n00b_result_err(int64_t, N00B_OBJ_BUNDLE_ERR_BUILD);
    }

    return n00b_result_ok(int64_t, verdict);
}

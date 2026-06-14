// WP-017 wrap-runtime FFI-target layer (D-052).
//
// Holds the runtime-global "current wrap context" and the plain-C FFI shims the
// EMBEDDED_N00B policy program calls. The wrap runtime (obj_bundle_wrap_run.c)
// sets the context before running the program and clears it after; the shims have
// no closure, so the runtime-global is how they reach the bundle.
//
// This is NOT the §11 const-char* shim layer (these shims take no libc-shaped
// params); it is the objfile-side FFI-target file, kept in compiler/objfile (not
// src/util) because it depends on the obj_bundle exec API — util must not depend
// on compiler/objfile.
//
// The wrap-context pointers are file-scope globals holding n00b allocations, so
// they are registered as GC roots (per the n00b-api-guidelines GC-root rule):
// otherwise a collection during the policy program's run could invalidate them.

#include "n00b.h"
#include "adt/result.h"
#include "adt/array.h"
#include "adt/list.h"
#include "adt/dict.h"
#include "core/gc.h"
#include "core/string.h"
#include "util/exec.h"
#include "util/path.h"
#include "compiler/objfile/obj_bundle.h"
#include "internal/compiler/objfile/obj_bundle_exec.h"

// Runtime-global wrap context. Set/cleared around a single policy-program run.
// The exec-target shim needs the bundle (to extract + exec its default target),
// the caller's allocator (NFR-04), and the passthrough argv — the args the
// wrapped binary was invoked with, forwarded to the embedded target so a wrapped
// `git` run as `git status` execs the real git with `status`.
static n00b_obj_bundle_t *wrap_ctx_bundle     = nullptr;
// The caller's allocator, threaded to the shim's extract/exec scratch (NFR-04).
// Borrowed, not owned: the wrap runtime sets this immediately before a single
// synchronous policy-program run and clears it immediately after (see
// _set/_clear below), so the pointer is only ever read within the caller's own
// stack frame, which strictly outlives the run. It is never freed here and never
// outlives _clear. Not a GC allocation (an allocator descriptor, not arena-
// managed), so deliberately not GC-rooted — §4.3 borrowed-allocator handle.
static n00b_allocator_t  *wrap_ctx_allocator  = nullptr;
// Passthrough args (each an n00b_string_t *), or nullptr for none. An n00b
// allocation holding n00b pointers, so GC-rooted alongside the bundle.
static n00b_array_t(n00b_string_t *) *wrap_ctx_argv = nullptr;
static bool               wrap_ctx_roots_done = false;

void
_n00b_obj_bundle_wrap_ctx_set(n00b_obj_bundle_t             *bundle,
                              n00b_allocator_t              *allocator,
                              n00b_array_t(n00b_string_t *) *argv)
{
    if (!wrap_ctx_roots_done) {
        // Register the n00b-pointer globals as GC roots once (after n00b_init,
        // which has run by the time any policy is executed).
        n00b_gc_register_root(wrap_ctx_bundle);
        n00b_gc_register_root(wrap_ctx_argv);
        wrap_ctx_roots_done = true;
    }

    wrap_ctx_bundle    = bundle;
    wrap_ctx_allocator = allocator;
    wrap_ctx_argv      = argv;
}

void
_n00b_obj_bundle_wrap_ctx_clear(void)
{
    wrap_ctx_bundle    = nullptr;
    wrap_ctx_allocator = nullptr;
    wrap_ctx_argv      = nullptr;
}

int64_t
n00b_wrap_exec_target_shim(void)
{
    if (wrap_ctx_bundle == nullptr) {
        return (int64_t)N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT;
    }

    // The EMBEDDED_N00B policy program IS the policy and has already decided
    // (the wrap runtime ran it). Exec the chosen target DIRECTLY — extract the
    // bundle and exec-replace — bypassing n00b_obj_bundle_exec_run, which would
    // re-evaluate this very bundle's EXECUTION-scope policy as a predicate
    // (clashing with the program model). Extraction is EXTRACTION-scope; this
    // bundle's policy is EXECUTION-scope, so no policy is re-triggered here.
    n00b_option_t(n00b_string_t *) logical_opt =
        _n00b_obj_bundle_default_exec_logical_path(wrap_ctx_bundle);

    if (!n00b_option_is_set(logical_opt)) {
        return (int64_t)N00B_OBJ_BUNDLE_ERR_MISSING_TARGET;
    }

    n00b_string_t *logical = n00b_option_get(logical_opt);

    auto temp_result = n00b_new_temp_dir(r"n00b-wrap-exec-", nullptr);

    if (n00b_result_is_err(temp_result)) {
        return (int64_t)N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED;
    }

    n00b_string_t *temp_root = n00b_result_get(temp_result);

    auto extract_result = n00b_obj_bundle_extract(wrap_ctx_bundle,
                                                  temp_root,
                                                  .overwrite = true,
                                                  .atomic    = false,
                                                  .allocator = wrap_ctx_allocator);

    if (n00b_result_is_err(extract_result)) {
        return (int64_t)N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED;
    }

    n00b_string_t *target = n00b_path_simple_join(temp_root, logical);

    // Proxy the wrapper's COMPLETE argv — including argv[0] — to the target, so
    // a wrapped `git` invoked as `git status` execs the real git with the exact
    // argv it was called with (argv[0] preserved: some binaries dispatch on it).
    // When there is no passthrough (e.g. a direct run_wrapped in a test), fall
    // back to a single-element argv of the target's logical name.
    n00b_array_t(n00b_string_t *) *exec_argv;

    if (wrap_ctx_argv != nullptr && n00b_array_len(*wrap_ctx_argv) > 0) {
        exec_argv = wrap_ctx_argv;
    }
    else {
        exec_argv  = n00b_alloc(n00b_array_t(n00b_string_t *));
        *exec_argv = n00b_array_new(n00b_string_t *, 1);
        n00b_array_set(*exec_argv, 0, logical);
    }

    // exec-replace. Returns ONLY on failure.
    auto exec_result = n00b_exec(target,
                                 .argv      = exec_argv,
                                 .allocator = wrap_ctx_allocator);

    (void)exec_result;
    return (int64_t)N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED;
}

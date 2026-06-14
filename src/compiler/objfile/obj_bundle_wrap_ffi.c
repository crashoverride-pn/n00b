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
#include "adt/list.h"
#include "adt/dict.h"
#include "core/gc.h"
#include "core/string.h"
#include "util/exec.h"
#include "util/path.h"
#include "compiler/objfile/obj_bundle.h"
#include "internal/compiler/objfile/obj_bundle_exec.h"

// Runtime-global wrap context. Set/cleared around a single policy-program run.
// MVP scope (D-052): the exec-target shim needs only the bundle (to extract +
// exec its default target) and the caller's allocator (NFR-04). Target argv/env
// passthrough is Phase 4 (the n00b-wrap host) and will add its own ctx fields
// then — kept minimal here to avoid dead-stored, dead-rooted globals.
static n00b_obj_bundle_t *wrap_ctx_bundle     = nullptr;
// The caller's allocator, threaded to the shim's extract/exec scratch (NFR-04).
// Not a GC allocation, so not GC-rooted.
static n00b_allocator_t  *wrap_ctx_allocator  = nullptr;
static bool               wrap_ctx_roots_done = false;

void
_n00b_obj_bundle_wrap_ctx_set(n00b_obj_bundle_t *bundle,
                              n00b_allocator_t  *allocator)
{
    if (!wrap_ctx_roots_done) {
        // Register the n00b-pointer global as a GC root once (after n00b_init,
        // which has run by the time any policy is executed).
        n00b_gc_register_root(wrap_ctx_bundle);
        wrap_ctx_roots_done = true;
    }

    wrap_ctx_bundle    = bundle;
    wrap_ctx_allocator = allocator;
}

void
_n00b_obj_bundle_wrap_ctx_clear(void)
{
    wrap_ctx_bundle    = nullptr;
    wrap_ctx_allocator = nullptr;
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
    n00b_string_t *logical =
        _n00b_obj_bundle_default_exec_logical_path(wrap_ctx_bundle);

    if (logical == nullptr) {
        return (int64_t)N00B_OBJ_BUNDLE_ERR_MISSING_TARGET;
    }

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

    // exec-replace. Returns ONLY on failure. (argv passthrough to the target is
    // Phase 4 / the n00b-wrap host; the MVP execs with no extra args.)
    auto exec_result = n00b_exec(target, .allocator = wrap_ctx_allocator);

    (void)exec_result;
    return (int64_t)N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED;
}

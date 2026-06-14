#pragma once

/**
 * @file obj_bundle_exec.h
 * @brief Internal cross-TU seam for the execute-from-bundle runner (WP-016).
 *
 * This header is a private declaration point shared between the neutral runner
 * (`obj_bundle_exec_run.c`, which defines the helper) and its callers
 * (`obj_bundle.c` plan resolution, the runner test). It is not part of the
 * public object-bundle API. Keeping the prototype here prevents the signature
 * from drifting silently across translation units.
 */

#include "compiler/objfile/obj_bundle.h"
#include "vfs/vfs.h"

/**
 * @brief Map a requested execution mode to a concrete, currently-available mode.
 *
 * Resolves `AUTO` (or an unsupported explicit request) using the per-platform
 * order (macOS `nfs -> extraction`; Linux `memfd -> extraction`; other:
 * extraction only), honoring @p allow_extraction_fallback.
 *
 * @param requested The caller-requested mode (may be `AUTO`).
 * @param allow_extraction_fallback Whether extraction may be selected as a
 *        fallback when no in-memory mode is available.
 * @return The selected concrete mode, or `N00B_OBJ_BUNDLE_EXEC_AUTO` as the
 *         "nothing available" sentinel.
 */
extern n00b_obj_bundle_exec_mode_t
_n00b_obj_bundle_exec_select_mode(n00b_obj_bundle_exec_mode_t requested,
                                  bool allow_extraction_fallback);

/**
 * @brief Pure (platform-free) mode-selection order logic.
 *
 * Same contract as @ref _n00b_obj_bundle_exec_select_mode, but the three host
 * availability results are supplied as parameters instead of probed, and the
 * body contains no `#if` — so the resolved per-platform order can be asserted
 * host-neutrally by feeding mocked probe values. The resolved AUTO order is
 * `nfs -> memfd -> extraction`; since NFS is macOS-only and memfd Linux-only, at
 * most one in-memory mode is ever available, so this uniform order matches the
 * per-platform contract. `_n00b_obj_bundle_exec_select_mode` is the thin wrapper
 * that supplies the live host probes.
 *
 * @return The selected concrete mode, or `N00B_OBJ_BUNDLE_EXEC_AUTO` as the
 *         "nothing available" sentinel.
 */
extern n00b_obj_bundle_exec_mode_t
_n00b_obj_bundle_exec_select_from_probes(n00b_obj_bundle_exec_mode_t requested,
                                         bool allow_extraction_fallback,
                                         bool nfs_available,
                                         bool memfd_available,
                                         bool extraction_available);

/**
 * @brief Whether the NFS execution mode is currently available on this host.
 *
 * True only on macOS AND when the setuid mount helper is present, executable,
 * and carries the setuid bit at its fixed install path; false everywhere else
 * (including Linux, where NFS mode is out of scope). Exposed for the gated
 * execution test so it can assert that mode selection stays consistent with the
 * actual host availability (which differs between a normal CI host with no
 * installed helper and a privileged host where the helper is installed).
 */
extern bool
_n00b_obj_bundle_exec_mode_nfs_available(void);

/**
 * @brief Whether the memfd execution mode is currently available on this host.
 *
 * True only on Linux (where `memfd_create`/`fexecve` exist); false everywhere
 * else (including macOS, where the memfd arm is `#if`-compiled out and execution
 * falls through to extraction). Exposed for the gated execution test so it can
 * assert that mode selection stays consistent with the actual host availability.
 */
extern bool
_n00b_obj_bundle_exec_mode_memfd_available(void);

/**
 * @brief Return the payload bytes of the artifact at @p logical_path.
 *
 * The in-memory NFS executor serves the selected target's bytes directly from
 * the decoded bundle artifact, never re-reading them from disk. This internal
 * seam lets the runner reach the artifact payload without exposing the private
 * artifact struct in the public API.
 *
 * @param bundle       Decoded object bundle.
 * @param logical_path Normalized logical path of the target artifact.
 * @return The artifact's payload buffer, or `nullptr` when no artifact matches
 *         @p logical_path or the matched artifact carries no payload.
 */
extern const n00b_buffer_t *
_n00b_obj_bundle_artifact_bytes_for_path(n00b_obj_bundle_t *bundle,
                                         n00b_string_t     *logical_path);

/**
 * @brief Number of artifacts in @p bundle (WP-017 VFS seam).
 *
 * Indexed-enumeration companions to @ref _n00b_obj_bundle_artifact_bytes_for_path:
 * they let the wrap runtime (`obj_bundle_wrap_run.c`) populate a VFS from the
 * bundle's artifacts WITHOUT dereferencing the file-private artifact struct (it is
 * visible only in `obj_bundle.c`, where these are defined). Like
 * `_n00b_obj_bundle_artifact_bytes_for_path`, these internal seam accessors carry
 * no ncc `requires`/`ensures` blocks — behavior is documented here, guards are
 * body-side.
 *
 * @param bundle Decoded object bundle (may be null).
 * @return The artifact count, or 0 for a null/empty bundle.
 */
extern int64_t
_n00b_obj_bundle_artifact_count(n00b_obj_bundle_t *bundle);

/**
 * @brief Logical path of the artifact at @p index.
 *
 * @param bundle Decoded object bundle.
 * @param index  Artifact index.
 * @pre `0 <= index < _n00b_obj_bundle_artifact_count(bundle)` — an out-of-range
 *      index is a caller bug, body-guarded by an `n00b_require` (not a trapping
 *      ncc `requires`). Pointer return → no `ensures` (D-029).
 * @return The artifact's normalized logical path (never null for a valid index).
 */
extern n00b_string_t *
_n00b_obj_bundle_artifact_logical_path_at(n00b_obj_bundle_t *bundle,
                                          int64_t            index);

/**
 * @brief Payload buffer of the artifact at @p index.
 *
 * @param bundle Decoded object bundle.
 * @param index  Artifact index.
 * @pre `0 <= index < _n00b_obj_bundle_artifact_count(bundle)` — body-guarded by an
 *      `n00b_require`. Pointer return → no `ensures` (D-029).
 * @return The artifact's payload buffer, or null for a payload-less artifact
 *         (e.g. a directory-kind artifact).
 */
extern const n00b_buffer_t *
_n00b_obj_bundle_artifact_payload_at(n00b_obj_bundle_t *bundle,
                                     int64_t            index);

/**
 * @brief Build an in-memory VFS exposing @p bundle's artifacts as a filesystem.
 *
 * The wrap runtime (WP-017) mounts the bundle's embedded objects as a VFS the
 * EMBEDDED_N00B policy program reads: an in-memory backend mounted at `/`,
 * populated with every artifact at its (normalized, relative) logical path under
 * the root, with intermediate directories created. Defined in
 * `obj_bundle_wrap_run.c`.
 *
 * @param bundle Decoded object bundle.
 * @kw allocator Allocator for the VFS + scratch (§4.1). (default: nullptr)
 *
 * @pre (advisory, D-031) @p bundle is non-null; a null bundle is a body-guarded
 *      `Err(N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT)`.
 * @post On Ok, every artifact is present in the VFS at its logical path (files
 *       carry their payload bytes; directory-kind artifacts and intermediate
 *       parents exist as directories).
 */
extern n00b_result_t(n00b_vfs_t *)
_n00b_obj_bundle_vfs_from_bundle(n00b_obj_bundle_t *bundle) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Source of the first EMBEDDED_N00B policy with @p scope.
 *
 * WP-017 D-052 seam: returns the PARSED n00b source string (not the raw envelope)
 * so the wrap runtime never re-implements the private policy-envelope format.
 * Defined in obj_bundle.c (sees `bundle->policies` + the envelope parser). No
 * `requires`/`ensures` (internal seam); a null bundle / missing policy /
 * unparseable envelope yields a body-guarded `none` (§5.4 — no nullptr sentinel).
 */
extern n00b_option_t(n00b_string_t *)
_n00b_obj_bundle_embedded_policy_source_for_scope(
    n00b_obj_bundle_t             *bundle,
    n00b_obj_bundle_policy_scope_t scope) _kargs {
    n00b_allocator_t *allocator = nullptr; // §4.1: this seam ALLOCATES the source
};

/**
 * @brief Logical path of @p bundle's default-exec target.
 *
 * WP-017 D-052 seam: the wrap exec shim extracts the bundle and execs this
 * target DIRECTLY (bypassing `exec_run`'s policy evaluation — the EMBEDDED_N00B
 * program is the policy and has already run). Defined in obj_bundle.c; no
 * requires/ensures (internal seam); `none` (§5.4 — no nullptr sentinel) when no
 * default-exec is set or it is unresolvable.
 */
extern n00b_option_t(n00b_string_t *)
_n00b_obj_bundle_default_exec_logical_path(n00b_obj_bundle_t *bundle);

/**
 * @brief Set / clear the runtime-global wrap context (WP-017 D-052).
 *
 * The wrap runtime sets the current bundle + the caller's allocator before
 * running the EMBEDDED_N00B policy program and clears it afterward, so the
 * plain-C policy FFI shims (which have no closure) can reach them. Defined in
 * `obj_bundle_wrap_ffi.c`. The bundle pointer is registered as a GC root there
 * (a file-scope global holding an n00b allocation); the allocator is not a GC
 * allocation, so it is not rooted. MVP scope is facts + exec; target argv/env
 * The @p argv is the passthrough argument vector (each element an
 * `n00b_string_t *`), forwarded to the embedded target so a wrapped command run
 * with arguments execs the real target with those arguments; nullptr for none.
 */
extern void
_n00b_obj_bundle_wrap_ctx_set(n00b_obj_bundle_t             *bundle,
                              n00b_allocator_t              *allocator,
                              n00b_array_t(n00b_string_t *) *argv);
extern void
_n00b_obj_bundle_wrap_ctx_clear(void);

/**
 * @brief Exec the current wrap-context bundle's selected target (FFI shim).
 *
 * Plain-C FFI target the EMBEDDED_N00B policy program calls (installed under an
 * n00b name by the wrap runtime). Reads the runtime-global wrap context and execs
 * its bundle's default target by resolving
 * `_n00b_obj_bundle_default_exec_logical_path`, extracting the bundle via
 * `n00b_obj_bundle_extract` (EXTRACTION scope), and exec-replacing via
 * `n00b_exec`. It deliberately does NOT go through `n00b_obj_bundle_exec_run`,
 * which would re-evaluate this bundle's EXECUTION-scope policy as a predicate —
 * but that policy IS the program the wrap runtime already ran. Returns ONLY on
 * failure (a nonzero error code); on success the process image is replaced and it
 * never returns.
 */
extern int64_t
n00b_wrap_exec_target_shim(void);

/**
 * @brief Compile and run a bundle's EMBEDDED_N00B policy as a full n00b PROGRAM.
 *
 * WP-017 D-052 wrap runtime (separate path; does NOT touch exec_run, the predicate
 * evaluator, the is_supported gates, or has_expression_start). Reads the
 * EXECUTION-scope EMBEDDED_N00B policy source, sets the runtime-global wrap
 * context, builds an eval session (`n00b_eval_session_new`), installs the policy
 * FFI shims, parses + annotates + runs the program
 * (`n00b_cg_session_run_module` → int64), then clears the wrap context.
 *
 * @param bundle Decoded object bundle carrying an EMBEDDED_N00B EXECUTION policy.
 * @kw allocator Allocator for the run scratch (§4.1). (default: nullptr)
 *
 * @pre (advisory, D-031) @p bundle non-null AND carries an EMBEDDED_N00B EXECUTION
 *      policy; otherwise a body-guarded Err.
 * @post On Ok, `result.ok` is the policy program's int64 verdict (a controller
 *       policy that execs a target via the shim never returns). The verdict is
 *       carried in `result.ok`, NOT asserted (no Ok-value ensures).
 * @kw argv Passthrough argument vector forwarded to the embedded target on the
 *      controller-exec path (each element an `n00b_string_t *`); default nullptr
 *      (the target is exec'd with just its own name). (default: nullptr)
 */
extern n00b_result_t(int64_t)
_n00b_obj_bundle_run_wrapped(n00b_obj_bundle_t *bundle) _kargs {
    n00b_allocator_t              *allocator = nullptr;
    n00b_array_t(n00b_string_t *) *argv      = nullptr;
};

/**
 * @brief Build an exec plan for an ALREADY-DECIDED target (no policy evaluation).
 *
 * WP-018 wrap-runtime seam: the EMBEDDED_N00B policy program has already run and
 * decided to exec, so there is no predicate to evaluate. This sets the selected
 * logical path + argv directly so the exec_run dispatcher can run the no-extract
 * executors (memfd/nfs/extraction) WITHOUT re-evaluating policy — the planner
 * rejects EMBEDDED_N00B as a predicate kind. Defined in obj_bundle.c.
 *
 * @param selected_logical Logical path of the already-decided target.
 * @param argv             Passthrough argv (each element an `n00b_string_t *`),
 *                         argv[0] included; nullptr for none.
 * @param env              Environment overlay, or nullptr (inherit).
 * @param mode             Resolved exec mode to record in the plan.
 * @kw allocator Allocator for the plan + scratch (§4.1). (default: nullptr)
 */
extern n00b_obj_bundle_exec_plan_t *
_n00b_obj_bundle_exec_plan_direct(n00b_string_t               *selected_logical,
                                  n00b_obj_bundle_exec_argv_t *argv,
                                  n00b_obj_bundle_exec_env_t  *env,
                                  n00b_obj_bundle_exec_mode_t  mode) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Exec-replace an already-decided bundle target via the no-extract
 *        executor stack (memfd→nfs→extraction), bypassing policy evaluation.
 *
 * WP-018 wrap-runtime seam. The wrap exec shim calls this AFTER the EMBEDDED_N00B
 * program decided to exec. It selects the best available no-extract mode (memfd
 * on Linux, NFS on macOS when privileged) and falls back to extraction, then
 * exec-replaces. On success the process image is replaced and this never returns;
 * the only returned value is the failure payload (Err, like
 * `n00b_obj_bundle_exec_run`). Defined in obj_bundle_exec_run.c.
 *
 * @param bundle           Decoded bundle carrying the target as an artifact.
 * @param selected_logical Logical path of the target to exec.
 * @param argv             Passthrough argv (argv[0] included); nullptr for none.
 * @kw allocator Allocator for the exec scratch (§4.1). (default: nullptr)
 */
extern n00b_result_t(bool)
_n00b_obj_bundle_exec_run_decided(n00b_obj_bundle_t           *bundle,
                                  n00b_string_t               *selected_logical,
                                  n00b_obj_bundle_exec_argv_t *argv) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

// Neutral execute-from-bundle runner (WP-016).
//
// The public API in compiler/objfile/obj_bundle.h is platform-neutral. This
// translation unit brings up the selected execution mode and either replaces
// the current process image (exec-replace, `n00b_obj_bundle_exec_run`) or runs
// the target as a child and waits (`n00b_obj_bundle_exec_spawn`).
//
// The OS-boundary calls reached here are the §2.10 raw-syscall exemptions
// (mirroring src/util/proc.c:1-9 and src/net/quic/metrics.c), each because
// libn00b has NO wrapper for the operation:
//   - `execv` (exec-REPLACE path): replacing the current process image.
//   - `memfd_create` (linux-only): creating an anonymous in-memory fd; there
//     is no n00b primitive for an anonymous fd.
//   - the raw `write` to the anonymous memfd (linux-only): there is NO n00b IO
//     wrapper for a bare anonymous fd (the conduit/file substrate operates on
//     named paths / managed owners, not an unnamed `memfd_create` fd). This is
//     the ONLY raw `write` here and it is confined to seeding the memfd payload
//     — it must NOT become general libc IO.
//   - `fexecve` (linux-only, exec-REPLACE path): replacing the current image
//     from an fd; there is no n00b wrapper for fd-based image replacement.
// The fork+wait (`exec_spawn`) variant does NOT use raw fork/waitpid — it runs
// the child through the n00b child-process primitive `n00b_subproc_*`. For the
// memfd mode the spawn path feeds `n00b_subproc` the anonymous fd's Linux procfs
// path `/proc/self/fd/<n>` (a real path on Linux), so the spawn path adds no raw
// syscall beyond `memfd_create` + the payload `write`.
//
// NFS mode (macOS-only, `#if defined(__MACH__)`): the in-memory loopback NFSv3
// serve is brought up through the n00b VFS layer; the privileged loopback
// `mount_nfs(8)` is performed by INVOKING the dedicated setuid-root helper
// (`n00b-nfs-mount-helper`) via `n00b_subproc_*` — NOT a raw mount syscall in
// this translation unit. The helper's own `execv("/sbin/mount_nfs", ...)` is
// justified in the helper's file header. NFS therefore adds NO new raw syscall
// to this executor beyond the already-justified `execv` image-replacement.
//
// memfd (linux-only, `#if defined(__linux__)`): the selected target's bytes are
// written into an anonymous `memfd_create` fd and executed in place via
// `fexecve` (run) or as a child via `n00b_subproc` on `/proc/self/fd/<n>`
// (spawn). The arm is `#if`-compiled OUT on macOS/other; this file wires
// extraction (all hosts), NFS (macOS), and memfd (Linux).

#include "n00b.h"
#include "adt/array.h"
#include "adt/dict.h"
#include "adt/list.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/env.h"
#include "core/runtime.h"
#include "core/string.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/subproc.h"
#include "text/strings/string_ops.h"
#include "util/path.h"
#include "compiler/objfile/obj_bundle.h"
#include "internal/compiler/objfile/obj_bundle_exec.h"

#if defined(__MACH__)
#include "core/buffer.h"
#include "vfs/vfs.h"
#include "vfs/backend_memory.h"
#include "vfs/frontend_nfs.h"
#include "vfs/frontend.h"
#include "vfs/types.h"
#endif

#if defined(__linux__)
// memfd_create lives in <sys/mman.h> (glibc). fexecve / write are in <unistd.h>
// (included below). n00b_cformat builds the /proc/self/fd/<n> path for the
// memfd spawn path. These are the only headers the linux-only memfd arm adds.
#include <sys/mman.h>
#include <errno.h>
#include "text/strings/format.h"
#endif

#include <unistd.h>

// Structured error-payload result shorthand (the OBJ_BUNDLE_ERR_PAYLOAD macro
// in obj_bundle.c is file-private; this is the same shape over the public
// n00b_result_err_payload).
#define EXEC_RUN_ERR(T, error)                                                  \
    n00b_result_err_payload(T, n00b_obj_bundle_error_t *, (error))

#if defined(__MACH__)
// Fixed install path of the darwin-only setuid mount helper. meson defines this
// from `get_option('prefix') / get_option('libexecdir') / name` so the runtime
// probe matches the install location. The fallback below keeps the file
// compilable without the build define; a non-default install prefix therefore
// changes the path the probe/invocation expect (deployment concern, OQ-2/OQ-3).
#ifndef N00B_NFS_MOUNT_HELPER_PATH
#define N00B_NFS_MOUNT_HELPER_PATH "/usr/local/libexec/n00b-nfs-mount-helper"
#endif

// Loopback NFSv3 serve port for the in-memory execute-from-bundle mode. Matches
// the proven de-risk sequence in src/tools/nfs_exec_poc.c. The string form is
// the same value, passed to the mount helper's fixed-shape argv; keep both in
// sync.
#define N00B_NFS_EXEC_PORT     20049
#define N00B_NFS_EXEC_PORT_STR "20049"
#endif

// Internal cross-TU helper implemented in obj_bundle.c.
extern n00b_obj_bundle_error_t *
_n00b_obj_bundle_error_make_exec(n00b_obj_bundle_error_code_t code,
                                 n00b_string_t               *message,
                                 n00b_obj_bundle_exec_mode_t  mode,
                                 n00b_string_t               *logical_path,
                                 n00b_allocator_t            *allocator);

// ----------------------------------------------------------------------------
// Exec-result record (opaque to callers; accessed via the accessor family).
// ----------------------------------------------------------------------------

struct n00b_obj_bundle_exec_result_record {
    n00b_obj_bundle_exec_mode_t resolved_mode;
    n00b_string_t              *launched_path;
    bool                        fallback_used;
    int64_t                     pid;
    int64_t                     exit_status;
    bool                        exited_normally;
};

// ----------------------------------------------------------------------------
// Mode availability probes. Parameterless host queries (no caller arena to
// forward). The extraction/memfd probes do not allocate; the NFS probe builds
// one short-lived n00b string for the host-path stat and immediately discards it
// (the probe returns only a bool, so the string is never retained — a transient
// default-heap allocation, not an arena-ownership concern or a leak).
// ----------------------------------------------------------------------------

static bool
_exec_mode_extraction_available(void)
{
    return true;
}

// Exposed (declared in obj_bundle_exec.h) so the gated execution test can assert
// that mode selection stays consistent with the real host availability.
bool
_n00b_obj_bundle_exec_mode_nfs_available(void)
{
#if defined(__MACH__)
    // OQ-3: "NFS available" == the setuid mount helper is present, executable,
    // and carries the setuid bit at the fixed install path. Absent / not-setuid
    // -> NFS "not allowed" -> selection falls through to extraction (fail safe).
    // The probe string is transient (discarded after the stat; see the section
    // comment), so it is intentionally built on the default heap.
    n00b_string_t *helper =
        n00b_string_from_cstr(N00B_NFS_MOUNT_HELPER_PATH);

    auto mode_result = n00b_path_get_mode(helper);

    if (n00b_result_is_err(mode_result)) {
        return false;
    }

    uint32_t mode = n00b_result_get(mode_result);

    // S_ISUID (04000) set AND some executable bit (owner/group/other) present.
    bool is_setuid     = (mode & 04000) != 0;
    bool is_executable = (mode & 0111) != 0;

    return is_setuid && is_executable;
#else
    // NFS is macOS-only (Linux = memfd -> extraction, no NFS); everywhere else
    // the mode is never available, so selection falls through.
    return false;
#endif
}

// Exposed (declared in obj_bundle_exec.h) so the gated execution test can assert
// that mode selection stays consistent with the real host availability.
bool
_n00b_obj_bundle_exec_mode_memfd_available(void)
{
#if defined(__linux__)
    // memfd_create + fexecve exist on Linux; the executor is compiled in here,
    // so the mode is available. (The memfd arm is #if-compiled OUT on every
    // other platform, where this probe returns false and selection falls
    // through to extraction.)
    return true;
#else
    return false;
#endif
}

// ----------------------------------------------------------------------------
// Shared selection helper. Contract documented at the cross-TU declaration in
// internal/compiler/objfile/obj_bundle_exec.h.
//
// The ORDER logic is factored into the pure, platform-free
// `_n00b_obj_bundle_exec_select_from_probes` (exposed for host-neutral order
// tests): it takes the three availability results as parameters and contains no
// `#if` and no probe calls, so the resolved per-platform order can be asserted
// on any host by feeding mocked probe values. `_n00b_obj_bundle_exec_select_mode`
// is the thin wrapper that supplies the live host probes. The AUTO order is a
// uniform `nfs -> memfd -> extraction`: NFS is macOS-only and memfd is
// Linux-only, so at most one in-memory mode is ever available, making the uniform
// order equivalent to the per-platform "nfs->extraction (macOS) / memfd->
// extraction (Linux)" contract without a platform branch.
// ----------------------------------------------------------------------------

n00b_obj_bundle_exec_mode_t
_n00b_obj_bundle_exec_select_from_probes(n00b_obj_bundle_exec_mode_t requested,
                                         bool allow_extraction_fallback,
                                         bool nfs_available,
                                         bool memfd_available,
                                         bool extraction_available)
{
    // An explicit, currently-available in-memory mode is honored directly; an
    // explicit-but-unavailable in-memory mode falls through to extraction (when
    // the caller permits it) or to the "nothing available" AUTO sentinel.
    if (requested == N00B_OBJ_BUNDLE_EXEC_NFS) {
        if (nfs_available) {
            return N00B_OBJ_BUNDLE_EXEC_NFS;
        }
        return allow_extraction_fallback && extraction_available
                   ? N00B_OBJ_BUNDLE_EXEC_EXTRACTED
                   : N00B_OBJ_BUNDLE_EXEC_AUTO;
    }

    if (requested == N00B_OBJ_BUNDLE_EXEC_MEMFD) {
        if (memfd_available) {
            return N00B_OBJ_BUNDLE_EXEC_MEMFD;
        }
        return allow_extraction_fallback && extraction_available
                   ? N00B_OBJ_BUNDLE_EXEC_EXTRACTED
                   : N00B_OBJ_BUNDLE_EXEC_AUTO;
    }

    if (requested == N00B_OBJ_BUNDLE_EXEC_EXTRACTED) {
        return extraction_available
                   ? N00B_OBJ_BUNDLE_EXEC_EXTRACTED
                   : N00B_OBJ_BUNDLE_EXEC_AUTO;
    }

    // AUTO (and any non-launchable planning mode treated as AUTO): the resolved
    // order — nfs, then memfd, then extraction (when fallback is permitted).
    if (nfs_available) {
        return N00B_OBJ_BUNDLE_EXEC_NFS;
    }
    if (memfd_available) {
        return N00B_OBJ_BUNDLE_EXEC_MEMFD;
    }
    if (allow_extraction_fallback && extraction_available) {
        return N00B_OBJ_BUNDLE_EXEC_EXTRACTED;
    }

    return N00B_OBJ_BUNDLE_EXEC_AUTO;
}

n00b_obj_bundle_exec_mode_t
_n00b_obj_bundle_exec_select_mode(n00b_obj_bundle_exec_mode_t requested,
                                  bool allow_extraction_fallback)
{
    return _n00b_obj_bundle_exec_select_from_probes(
        requested,
        allow_extraction_fallback,
        _n00b_obj_bundle_exec_mode_nfs_available(),
        _n00b_obj_bundle_exec_mode_memfd_available(),
        _exec_mode_extraction_available());
}

// ----------------------------------------------------------------------------
// Error helpers.
// ----------------------------------------------------------------------------

static n00b_obj_bundle_error_t *
_exec_error(n00b_obj_bundle_error_code_t code,
            n00b_string_t               *message,
            n00b_obj_bundle_exec_mode_t  mode,
            n00b_string_t               *logical_path,
            n00b_allocator_t            *allocator)
{
    return _n00b_obj_bundle_error_make_exec(code,
                                            message,
                                            mode,
                                            logical_path,
                                            allocator);
}

// ----------------------------------------------------------------------------
// Plan-fact extraction shared by both entry points.
// ----------------------------------------------------------------------------

static n00b_result_t(n00b_obj_bundle_exec_plan_t *)
_exec_make_plan(n00b_obj_bundle_t             *bundle,
                n00b_string_t                 *selector,
                n00b_obj_bundle_exec_argv_t   *argv,
                n00b_obj_bundle_exec_env_t    *env,
                bool                           inherit_env,
                bool                           strict_selector,
                n00b_obj_bundle_exec_mode_t    mode,
                n00b_obj_bundle_policy_mode_t  policy_mode,
                n00b_allocator_t              *allocator)
{
    return n00b_obj_bundle_exec_plan(bundle,
                                     .selector        = selector,
                                     .argv            = argv,
                                     .env             = env,
                                     .inherit_env     = inherit_env,
                                     .strict_selector = strict_selector,
                                     .mode            = mode,
                                     .policy_mode     = policy_mode,
                                     .allocator       = allocator);
}

// Flatten the plan's env dict into a "KEY=VALUE" string array for n00b_subproc.
// Returns nullptr when there is no overlay (subproc null env = inherit).
static n00b_array_t(n00b_string_t *) *
_exec_env_to_array(n00b_obj_bundle_exec_env_t *env, n00b_allocator_t *allocator)
{
    if (env == nullptr) {
        return nullptr;
    }

    int64_t count = 0;
    n00b_dict_foreach(env, key, value, {
        (void)key;
        (void)value;
        count++;
    });

    n00b_array_t(n00b_string_t *) *out =
        n00b_alloc(n00b_array_t(n00b_string_t *), .allocator = allocator);

    *out = n00b_array_new(n00b_string_t *,
                          count == 0 ? 1 : count,
                          .allocator = allocator);

    n00b_dict_foreach(env, key, value, {
        n00b_string_t *kv =
            n00b_unicode_str_cat(key, r"=", .allocator = allocator);
        n00b_string_t *entry =
            n00b_unicode_str_cat(kv, value, .allocator = allocator);
        size_t idx = n00b_array_len(*out);
        n00b_array_set(*out, idx, entry);
    });

    return out;
}

// Convert the plan's argv list into an n00b_array for n00b_subproc.
static n00b_array_t(n00b_string_t *) *
_exec_argv_to_array(n00b_obj_bundle_exec_argv_t *argv,
                    n00b_allocator_t            *allocator)
{
    size_t n = argv == nullptr ? 0 : n00b_list_len(*argv);

    n00b_array_t(n00b_string_t *) *out =
        n00b_alloc(n00b_array_t(n00b_string_t *), .allocator = allocator);

    *out = n00b_array_new(n00b_string_t *, (int64_t)(n == 0 ? 1 : n),
                          .allocator = allocator);

    for (size_t i = 0; i < n; i++) {
        n00b_array_set(*out, i, n00b_list_get(*argv, i));
    }

    return out;
}

// ----------------------------------------------------------------------------
// Shared subprocess helpers (n00b_subproc_*; NEVER raw fork/waitpid).
// ----------------------------------------------------------------------------

// Spawn @p cmd_path with @p argv_array / @p env_array as a child, wait, and
// populate a fresh exec-result with @p resolved_mode / @p launched_path /
// @p fallback_used and the child's pid + exit/term outcome. Shared by the
// extraction spawn path and the NFS spawn path so the conduit/io/subproc
// wiring lives in one place. Returns Err(EXEC_LAUNCH_FAILED) on bring-up
// failure (with @p resolved_mode / @p launched_path attached for diagnostics).
static n00b_result_t(n00b_obj_bundle_exec_result_t *)
_exec_spawn_child_result(n00b_string_t                 *cmd_path,
                         n00b_array_t(n00b_string_t *) *argv_array,
                         n00b_array_t(n00b_string_t *) *env_array,
                         n00b_obj_bundle_exec_mode_t    resolved_mode,
                         n00b_string_t                 *launched_path,
                         bool                           fallback_used,
                         n00b_allocator_t              *allocator)
{
    auto conduit_result = n00b_conduit_new();

    if (n00b_result_is_err(conduit_result)) {
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED,
                        r"object bundle: conduit creation failed",
                        resolved_mode,
                        launched_path,
                        allocator));
    }

    n00b_conduit_t *conduit   = n00b_result_get(conduit_result);
    auto            io_result = n00b_conduit_io_new_default(conduit);

    if (n00b_result_is_err(io_result)) {
        n00b_conduit_destroy(conduit);
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED,
                        r"object bundle: conduit io backend creation failed",
                        resolved_mode,
                        launched_path,
                        allocator));
    }

    n00b_conduit_io_backend_t *io = n00b_result_get(io_result);
    n00b_subproc_t            *sp =
        n00b_alloc(n00b_subproc_t, .allocator = allocator);

    n00b_subproc_init(sp,
                      .cmd            = cmd_path,
                      .conduit        = conduit,
                      .io             = io,
                      .args           = argv_array,
                      .env            = env_array,
                      .raw_argv       = true,
                      .done_condition = N00B_SUBPROC_DONE_PROC_EXIT);

    auto run_result = n00b_subproc_run(sp);

    if (n00b_result_is_err(run_result)) {
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(conduit);
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED,
                        r"object bundle: child launch failed",
                        resolved_mode,
                        launched_path,
                        allocator));
    }

    n00b_obj_bundle_exec_result_t *result =
        n00b_alloc(n00b_obj_bundle_exec_result_t, .allocator = allocator);

    result->resolved_mode = resolved_mode;
    result->launched_path = launched_path;
    result->fallback_used = fallback_used;

    auto pid_opt = n00b_subproc_pid(sp);
    result->pid  = n00b_option_is_set(pid_opt)
                       ? (int64_t)n00b_option_get(pid_opt)
                       : -1;

    auto exit_code = n00b_subproc_exit_code(sp);

    if (n00b_result_is_ok(exit_code)) {
        result->exited_normally = true;
        result->exit_status     = (int64_t)n00b_result_get(exit_code);
    }
    else {
        auto term = n00b_subproc_term_signal(sp);

        result->exited_normally = false;
        result->exit_status     = n00b_result_is_ok(term)
                                      ? (int64_t)n00b_result_get(term)
                                      : -1;
    }

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(conduit);

    return n00b_result_ok(n00b_obj_bundle_exec_result_t *, result);
}

#if defined(__MACH__)
// Run @p cmd_path with @p argv_array (raw argv, inherited env) as a child via
// n00b_subproc and wait. Returns Ok(exit_code) when the child exited normally,
// or Err(EXEC_LAUNCH_FAILED) when bring-up failed / the child was signaled.
// Used by the NFS executor to invoke the setuid mount helper and /sbin/umount
// — the privileged mount/unmount goes through a child process, never a raw
// mount syscall in this translation unit.
static n00b_result_t(int)
_exec_run_command(n00b_string_t                 *cmd_path,
                  n00b_array_t(n00b_string_t *) *argv_array,
                  n00b_allocator_t              *allocator)
{
    auto conduit_result = n00b_conduit_new();

    if (n00b_result_is_err(conduit_result)) {
        return n00b_result_err(int, N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED);
    }

    n00b_conduit_t *conduit   = n00b_result_get(conduit_result);
    auto            io_result = n00b_conduit_io_new_default(conduit);

    if (n00b_result_is_err(io_result)) {
        n00b_conduit_destroy(conduit);
        return n00b_result_err(int, N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED);
    }

    n00b_conduit_io_backend_t *io = n00b_result_get(io_result);
    n00b_subproc_t            *sp =
        n00b_alloc(n00b_subproc_t, .allocator = allocator);

    n00b_subproc_init(sp,
                      .cmd            = cmd_path,
                      .conduit        = conduit,
                      .io             = io,
                      .args           = argv_array,
                      .raw_argv       = true,
                      .done_condition = N00B_SUBPROC_DONE_PROC_EXIT);

    auto run_result = n00b_subproc_run(sp);

    if (n00b_result_is_err(run_result)) {
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(conduit);
        return n00b_result_err(int, N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED);
    }

    auto exit_code = n00b_subproc_exit_code(sp);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(conduit);

    if (n00b_result_is_err(exit_code)) {
        return n00b_result_err(int, N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED);
    }

    return n00b_result_ok(int, n00b_result_get(exit_code));
}
#endif // __MACH__

// ----------------------------------------------------------------------------
// Extraction executor.
//
// Extracts the selected target to a fresh temp root, joins the extracted root
// with the plan's selected logical path, then either exec-replaces (run) via
// raw execv or runs the child via n00b_subproc and waits (spawn).
// ----------------------------------------------------------------------------

static n00b_result_t(n00b_obj_bundle_exec_result_t *)
_exec_via_extraction(n00b_obj_bundle_t           *bundle,
                     n00b_obj_bundle_exec_plan_t *plan,
                     bool                         fork_and_wait,
                     bool                         fallback_used,
                     n00b_allocator_t            *allocator)
{
    auto selected_opt = n00b_obj_bundle_exec_plan_selected_logical_path(plan);

    if (!n00b_option_is_set(selected_opt)) {
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                        r"object bundle: extraction has no selected target",
                        N00B_OBJ_BUNDLE_EXEC_EXTRACTED,
                        nullptr,
                        allocator));
    }

    n00b_string_t *logical_path = n00b_option_get(selected_opt);

    auto temp_root_result =
        n00b_new_temp_dir(r"n00b-obj-bundle-exec-", nullptr);

    if (n00b_result_is_err(temp_root_result)) {
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED,
                        r"object bundle: extraction temp root creation failed",
                        N00B_OBJ_BUNDLE_EXEC_EXTRACTED,
                        logical_path,
                        allocator));
    }

    n00b_string_t *temp_root = n00b_result_get(temp_root_result);

    auto extract_result = n00b_obj_bundle_extract(bundle,
                                                  temp_root,
                                                  .overwrite = true,
                                                  .atomic    = false,
                                                  .allocator = allocator);

    if (n00b_result_is_err(extract_result)) {
        if (n00b_result_is_err_payload(n00b_obj_bundle_error_t *,
                                       extract_result)) {
            return EXEC_RUN_ERR(
                n00b_obj_bundle_exec_result_t *,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            extract_result));
        }

        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED,
                        r"object bundle: extraction failed",
                        N00B_OBJ_BUNDLE_EXEC_EXTRACTED,
                        logical_path,
                        allocator));
    }

    n00b_string_t *target_path =
        n00b_path_simple_join(temp_root, logical_path);

    auto argv_opt = n00b_obj_bundle_exec_plan_argv(plan);
    n00b_obj_bundle_exec_argv_t *argv =
        n00b_option_is_set(argv_opt) ? n00b_option_get(argv_opt) : nullptr;
    auto env_opt = n00b_obj_bundle_exec_plan_env(plan);
    n00b_obj_bundle_exec_env_t *env =
        n00b_option_is_set(env_opt) ? n00b_option_get(env_opt) : nullptr;

    n00b_array_t(n00b_string_t *) *argv_array =
        _exec_argv_to_array(argv, allocator);
    n00b_array_t(n00b_string_t *) *env_array =
        _exec_env_to_array(env, allocator);

    if (!fork_and_wait) {
        // EXEC-REPLACE. §2.10: no n00b wrapper exists for replacing the current
        // process image, so this is the single justified raw OS-boundary call.
        size_t  n   = n00b_array_len(*argv_array);
        char  **raw = n00b_alloc_array(char *, n + 1, .allocator = allocator);

        // raw[] holds interior `->data` pointers into managed strings. The
        // backing strings stay reachable through the live argv_array, and the
        // array allocation above is the LAST allocation before execv: no
        // allocation (and therefore no GC move) occurs between filling raw[]
        // and the execv call, so the interior pointers remain valid.
        size_t i = 0;
        while (i < n) {
            n00b_string_t *arg = n00b_array_get(*argv_array, i);
            raw[i]             = arg->data;
            i++;
        }
        raw[n] = nullptr;

        execv(target_path->data, raw);

        // execv only returns on failure.
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED,
                        r"object bundle: exec-replace of extracted target failed",
                        N00B_OBJ_BUNDLE_EXEC_EXTRACTED,
                        logical_path,
                        allocator));
    }

    // FORK+WAIT via the n00b child-process primitive (NOT raw fork/waitpid).
    return _exec_spawn_child_result(target_path,
                                    argv_array,
                                    env_array,
                                    N00B_OBJ_BUNDLE_EXEC_EXTRACTED,
                                    logical_path,
                                    fallback_used,
                                    allocator);
}

#if defined(__MACH__)
// ----------------------------------------------------------------------------
// NFS executor (macOS-only).
//
// Ports the proven serve->mount->exec sequence in src/tools/nfs_exec_poc.c to
// n00b primitives. Builds an in-memory VFS, serves the selected target's bytes
// (pulled from the BUNDLE artifact, never re-read from disk) over a loopback
// NFSv3 server, mounts it by INVOKING the setuid mount helper via n00b_subproc
// (NOT a raw mount syscall here), then exec-replaces (run) or runs the served
// path as a child and waits (spawn). On the spawn path the mount and frontend
// are torn down before returning; the run path exec-replaces, so the mount /
// frontend persist for the new image.
// ----------------------------------------------------------------------------

static n00b_result_t(n00b_obj_bundle_exec_result_t *)
_exec_via_nfs(n00b_obj_bundle_t           *bundle,
              n00b_obj_bundle_exec_plan_t *plan,
              bool                         fork_and_wait,
              bool                         fallback_used,
              n00b_allocator_t            *allocator)
{
    auto selected_opt = n00b_obj_bundle_exec_plan_selected_logical_path(plan);

    if (!n00b_option_is_set(selected_opt)) {
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                        r"object bundle: NFS mode has no selected target",
                        N00B_OBJ_BUNDLE_EXEC_NFS,
                        nullptr,
                        allocator));
    }

    n00b_string_t *logical_path = n00b_option_get(selected_opt);

    // Served bytes come from the decoded bundle artifact, NOT from disk.
    const n00b_buffer_t *payload =
        _n00b_obj_bundle_artifact_bytes_for_path(bundle, logical_path);

    if (payload == nullptr) {
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                        r"object bundle: NFS target artifact has no bytes",
                        N00B_OBJ_BUNDLE_EXEC_NFS,
                        logical_path,
                        allocator));
    }

    // n00b_vfs_write copies the bytes into the handle's pending write image, so
    // the borrowed (const) artifact payload can be passed through directly. The
    // const is dropped only at this hand-off; the write does not mutate it.
    n00b_buffer_t *bytes = (n00b_buffer_t *)payload;

    // 1. Build a VFS with an in-memory backend mounted at "/".
    auto vfs_result = n00b_vfs_new(.allocator = allocator);

    if (n00b_result_is_err(vfs_result)) {
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED,
                        r"object bundle: NFS vfs creation failed",
                        N00B_OBJ_BUNDLE_EXEC_NFS,
                        logical_path,
                        allocator));
    }

    n00b_vfs_t *vfs = n00b_result_get(vfs_result);

    auto backend_result = n00b_vfs_backend_memory_new(.allocator = allocator);

    if (n00b_result_is_err(backend_result)) {
        n00b_vfs_destroy(vfs);
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED,
                        r"object bundle: NFS memory backend creation failed",
                        N00B_OBJ_BUNDLE_EXEC_NFS,
                        logical_path,
                        allocator));
    }

    n00b_vfs_backend_t *backend = n00b_result_get(backend_result);

    if (n00b_result_is_err(n00b_vfs_mount(vfs, r"/", backend, 0))) {
        n00b_vfs_destroy(vfs);
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED,
                        r"object bundle: NFS vfs mount failed",
                        N00B_OBJ_BUNDLE_EXEC_NFS,
                        logical_path,
                        allocator));
    }

    // The NFS client GETATTRs / LOOKUPs the export root; an in-memory backend
    // has no implicit root, so create it explicitly (mirrors the PoC).
    n00b_vfs_mkdir(vfs, r"/");

    // 2. Put the served binary bytes at a fixed VFS path.
    n00b_string_t *vpath = r"/prog";

    auto open_result = n00b_vfs_open(vfs, vpath, N00B_VFS_O_W);

    if (n00b_result_is_err(open_result)) {
        n00b_vfs_destroy(vfs);
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED,
                        r"object bundle: NFS vfs open failed",
                        N00B_OBJ_BUNDLE_EXEC_NFS,
                        logical_path,
                        allocator));
    }

    n00b_vfs_fh_t fh = n00b_result_get(open_result);
    n00b_vfs_write(vfs, fh, bytes);
    n00b_vfs_close(vfs, fh);

    // 3. Mount point under a fresh temp dir.
    auto mount_dir_result =
        n00b_new_temp_dir(r"n00b-obj-bundle-nfs-", nullptr);

    if (n00b_result_is_err(mount_dir_result)) {
        n00b_vfs_destroy(vfs);
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED,
                        r"object bundle: NFS mount point creation failed",
                        N00B_OBJ_BUNDLE_EXEC_NFS,
                        logical_path,
                        allocator));
    }

    n00b_string_t *mount_point = n00b_result_get(mount_dir_result);

    // 4. Start the loopback NFSv3 server over the VFS.
    auto fe_result =
        n00b_vfs_frontend_nfs_new(vfs, mount_point, N00B_NFS_EXEC_PORT);

    if (n00b_result_is_err(fe_result)) {
        n00b_vfs_destroy(vfs);
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED,
                        r"object bundle: NFS frontend creation failed",
                        N00B_OBJ_BUNDLE_EXEC_NFS,
                        logical_path,
                        allocator));
    }

    n00b_vfs_frontend_t *fe = n00b_result_get(fe_result);

    if (n00b_result_is_err(n00b_vfs_frontend_start(fe))) {
        n00b_vfs_frontend_stop(fe);
        n00b_vfs_destroy(vfs);
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED,
                        r"object bundle: NFS frontend start failed",
                        N00B_OBJ_BUNDLE_EXEC_NFS,
                        logical_path,
                        allocator));
    }

    // 5. Mount it by INVOKING the setuid helper via n00b_subproc. The helper
    // takes a fixed-shape argv: <tcp-port> <absolute-mount-point>.
    n00b_string_t *port_str =
        n00b_string_from_cstr(N00B_NFS_EXEC_PORT_STR, .allocator = allocator);

    n00b_string_t *helper_path =
        n00b_string_from_cstr(N00B_NFS_MOUNT_HELPER_PATH, .allocator = allocator);

    n00b_array_t(n00b_string_t *) mount_argv =
        n00b_array_new(n00b_string_t *, 3, .allocator = allocator);
    n00b_array_set(mount_argv, 0, helper_path);
    n00b_array_set(mount_argv, 1, port_str);
    n00b_array_set(mount_argv, 2, mount_point);

    auto mount_rc = _exec_run_command(helper_path, &mount_argv, allocator);

    if (n00b_result_is_err(mount_rc) || n00b_result_get(mount_rc) != 0) {
        n00b_vfs_frontend_stop(fe);
        n00b_vfs_destroy(vfs);
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED,
                        r"object bundle: NFS mount helper failed",
                        N00B_OBJ_BUNDLE_EXEC_NFS,
                        logical_path,
                        allocator));
    }

    // The served on-disk path is <mount_point>/prog. Join with the RELATIVE leaf
    // (not vpath, which is the absolute in-VFS path "/prog" — joining an absolute
    // second component would discard mount_point and yield "/prog").
    n00b_string_t *served_path = n00b_path_simple_join(mount_point, r"prog");

    auto argv_opt = n00b_obj_bundle_exec_plan_argv(plan);
    n00b_obj_bundle_exec_argv_t *argv =
        n00b_option_is_set(argv_opt) ? n00b_option_get(argv_opt) : nullptr;
    auto env_opt = n00b_obj_bundle_exec_plan_env(plan);
    n00b_obj_bundle_exec_env_t *env =
        n00b_option_is_set(env_opt) ? n00b_option_get(env_opt) : nullptr;

    n00b_array_t(n00b_string_t *) *argv_array =
        _exec_argv_to_array(argv, allocator);
    n00b_array_t(n00b_string_t *) *env_array =
        _exec_env_to_array(env, allocator);

    if (!fork_and_wait) {
        // EXEC-REPLACE. §2.10: no n00b wrapper exists for replacing the current
        // process image. The mount + frontend persist for the new image.
        size_t  n   = n00b_array_len(*argv_array);
        char  **raw = n00b_alloc_array(char *, n + 1, .allocator = allocator);

        // raw[] holds interior `->data` pointers into managed strings. The
        // backing strings stay reachable through the live argv_array, and the
        // array allocation above is the LAST allocation before execv: no
        // allocation (and therefore no GC move) occurs between filling raw[]
        // and the execv call, so the interior pointers remain valid.
        size_t i = 0;
        while (i < n) {
            n00b_string_t *arg = n00b_array_get(*argv_array, i);
            raw[i]             = arg->data;
            i++;
        }
        raw[n] = nullptr;

        execv(served_path->data, raw);

        // execv only returns on failure. Tear down the mount/frontend so the
        // failed launch leaves no dangling loopback export behind.
        n00b_string_t *umount_path =
            n00b_string_from_cstr("/sbin/umount", .allocator = allocator);
        n00b_array_t(n00b_string_t *) umount_argv =
            n00b_array_new(n00b_string_t *, 2, .allocator = allocator);
        n00b_array_set(umount_argv, 0, umount_path);
        n00b_array_set(umount_argv, 1, mount_point);
        _exec_run_command(umount_path, &umount_argv, allocator);
        n00b_vfs_frontend_stop(fe);
        n00b_vfs_destroy(vfs);

        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED,
                        r"object bundle: exec-replace of NFS-served target failed",
                        N00B_OBJ_BUNDLE_EXEC_NFS,
                        logical_path,
                        allocator));
    }

    // SPAWN: run the served path as a child and wait, then unmount + stop.
    auto result = _exec_spawn_child_result(served_path,
                                           argv_array,
                                           env_array,
                                           N00B_OBJ_BUNDLE_EXEC_NFS,
                                           logical_path,
                                           fallback_used,
                                           allocator);

    // Always tear down the mount + frontend on the spawn path, whether or not
    // the child launched, so nothing is left mounted from this run.
    n00b_string_t *umount_path =
        n00b_string_from_cstr("/sbin/umount", .allocator = allocator);
    n00b_array_t(n00b_string_t *) umount_argv =
        n00b_array_new(n00b_string_t *, 2, .allocator = allocator);
    n00b_array_set(umount_argv, 0, umount_path);
    n00b_array_set(umount_argv, 1, mount_point);
    _exec_run_command(umount_path, &umount_argv, allocator);

    n00b_vfs_unmount(vfs, r"/");
    n00b_vfs_frontend_stop(fe);
    n00b_vfs_destroy(vfs);

    return result;
}
#endif // __MACH__

#if defined(__linux__)
// ----------------------------------------------------------------------------
// memfd executor (Linux-only).
//
// Writes the selected target's bytes (pulled from the BUNDLE artifact, never
// re-read from disk) into an anonymous `memfd_create` fd, then exec-replaces in
// place via `fexecve` (run) or runs the fd as a child via n00b_subproc on its
// Linux procfs path `/proc/self/fd/<n>` (spawn). All raw OS-boundary calls
// (memfd_create, the payload write, fexecve) are §2.10-justified in the file
// header — each lacks a n00b wrapper for an anonymous fd / fd-based image
// replacement.
// ----------------------------------------------------------------------------

static n00b_result_t(n00b_obj_bundle_exec_result_t *)
_exec_via_memfd(n00b_obj_bundle_t           *bundle,
                n00b_obj_bundle_exec_plan_t *plan,
                bool                         fork_and_wait,
                bool                         fallback_used,
                n00b_allocator_t            *allocator)
{
    auto selected_opt = n00b_obj_bundle_exec_plan_selected_logical_path(plan);

    if (!n00b_option_is_set(selected_opt)) {
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                        r"object bundle: memfd mode has no selected target",
                        N00B_OBJ_BUNDLE_EXEC_MEMFD,
                        nullptr,
                        allocator));
    }

    n00b_string_t *logical_path = n00b_option_get(selected_opt);

    // Served bytes come from the decoded bundle artifact, NOT from disk.
    const n00b_buffer_t *payload =
        _n00b_obj_bundle_artifact_bytes_for_path(bundle, logical_path);

    if (payload == nullptr) {
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                        r"object bundle: memfd target artifact has no bytes",
                        N00B_OBJ_BUNDLE_EXEC_MEMFD,
                        logical_path,
                        allocator));
    }

    // 1. Create the anonymous in-memory fd. §2.10: no n00b wrapper for an
    // anonymous fd. MFD_CLOEXEC so the fd does not leak into the child on the
    // spawn path (the procfs path keeps it reachable for that exec).
    int fd = memfd_create("n00b-obj-bundle-exec", MFD_CLOEXEC);

    if (fd < 0) {
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED,
                        r"object bundle: memfd_create failed",
                        N00B_OBJ_BUNDLE_EXEC_MEMFD,
                        logical_path,
                        allocator));
    }

    // 2. Seed the payload into the anonymous fd. §2.10: the ONLY raw write here
    // — there is no n00b IO wrapper for a bare anonymous (unnamed) fd. Loop to
    // handle short writes.
    const char *bytes = payload->data;
    size_t      total = payload->byte_len;
    size_t      done  = 0;

    while (done < total) {
        ssize_t w = write(fd, bytes + done, total - done);

        if (w < 0) {
            // A signal (e.g. SIGCHLD from a prior subproc reap) can interrupt
            // write with EINTR; that is transient — retry rather than fail.
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return EXEC_RUN_ERR(
                n00b_obj_bundle_exec_result_t *,
                _exec_error(
                    N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED,
                    r"object bundle: memfd payload write failed",
                    N00B_OBJ_BUNDLE_EXEC_MEMFD,
                    logical_path,
                    allocator));
        }

        done += (size_t)w;
    }

    // 3. Build argv/env from the plan.
    auto argv_opt = n00b_obj_bundle_exec_plan_argv(plan);
    n00b_obj_bundle_exec_argv_t *argv =
        n00b_option_is_set(argv_opt) ? n00b_option_get(argv_opt) : nullptr;
    auto env_opt = n00b_obj_bundle_exec_plan_env(plan);
    n00b_obj_bundle_exec_env_t *env =
        n00b_option_is_set(env_opt) ? n00b_option_get(env_opt) : nullptr;

    n00b_array_t(n00b_string_t *) *argv_array =
        _exec_argv_to_array(argv, allocator);
    n00b_array_t(n00b_string_t *) *env_array =
        _exec_env_to_array(env, allocator);

    if (!fork_and_wait) {
        // EXEC-REPLACE via fexecve. §2.10: no n00b wrapper for fd-based image
        // replacement.
        size_t  n   = n00b_array_len(*argv_array);
        char  **raw = n00b_alloc_array(char *, n + 1, .allocator = allocator);

        // raw[]/envp[] hold interior `->data` pointers into managed strings.
        // The backing strings stay reachable through the live argv_array/
        // env_array, and these array allocations are the LAST allocations before
        // fexecve: no allocation (and therefore no GC move) occurs between
        // filling raw[]/envp[] and the fexecve call, so the interior pointers
        // remain valid (mirrors the extraction execv pattern above).
        size_t i = 0;
        while (i < n) {
            n00b_string_t *arg = n00b_array_get(*argv_array, i);
            raw[i]             = arg->data;
            i++;
        }
        raw[n] = nullptr;

        char **envp = nullptr;

        if (env_array != nullptr) {
            size_t en = n00b_array_len(*env_array);
            envp = n00b_alloc_array(char *, en + 1, .allocator = allocator);

            size_t j = 0;
            while (j < en) {
                n00b_string_t *e = n00b_array_get(*env_array, j);
                envp[j]          = e->data;
                j++;
            }
            envp[en] = nullptr;
        }

        // A null env inherits the current environment; with no n00b wrapper for
        // the raw environ pointer, pass the current environ through directly.
        extern char **environ;
        fexecve(fd, raw, envp != nullptr ? envp : environ);

        // fexecve only returns on failure.
        close(fd);
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED,
                        r"object bundle: fexecve of memfd target failed",
                        N00B_OBJ_BUNDLE_EXEC_MEMFD,
                        logical_path,
                        allocator));
    }

    // SPAWN: run the anonymous fd through n00b_subproc via its Linux procfs path
    // (a real path on Linux) — NOT raw fork/waitpid. The fd is MFD_CLOEXEC, but
    // /proc/self/fd/<n> is resolved by the kernel before exec, so the child can
    // still exec it.
    // n00b_cformat (like n00b_format) has no `.allocator` kwarg, so this builds
    // on the default heap; the path is transient — consumed immediately by the
    // subproc launch below and never retained — so there is no arena-ownership
    // concern (it cannot be threaded through the caller's allocator here).
    n00b_string_t *fd_path =
        n00b_cformat("/proc/self/fd/[|#|]", (int64_t)fd);

    auto result = _exec_spawn_child_result(fd_path,
                                           argv_array,
                                           env_array,
                                           N00B_OBJ_BUNDLE_EXEC_MEMFD,
                                           logical_path,
                                           fallback_used,
                                           allocator);

    close(fd);

    return result;
}
#endif // __linux__

// ----------------------------------------------------------------------------
// Shared dispatch.
// ----------------------------------------------------------------------------

static n00b_result_t(n00b_obj_bundle_exec_result_t *)
_exec_dispatch(n00b_obj_bundle_t             *bundle,
               n00b_string_t                 *selector,
               n00b_obj_bundle_exec_argv_t   *argv,
               n00b_obj_bundle_exec_env_t    *env,
               bool                           inherit_env,
               bool                           strict_selector,
               n00b_obj_bundle_exec_mode_t    mode,
               n00b_obj_bundle_policy_mode_t  policy_mode,
               bool                           allow_extraction_fallback,
               bool                           fork_and_wait,
               n00b_allocator_t              *allocator)
{
    if (bundle == nullptr) {
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                        r"object bundle: null execution bundle",
                        mode,
                        nullptr,
                        allocator));
    }

    n00b_obj_bundle_exec_mode_t selected =
        _n00b_obj_bundle_exec_select_mode(mode, allow_extraction_fallback);

    if (selected == N00B_OBJ_BUNDLE_EXEC_AUTO) {
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_NO_MODE_AVAILABLE,
                        r"object bundle: no execution mode available",
                        mode,
                        nullptr,
                        allocator));
    }

    bool fallback_used = mode != N00B_OBJ_BUNDLE_EXEC_AUTO && selected != mode;

    // Build the plan (selection, policy evaluation, argv/env planning).
    // Record the resolved mode the executor will actually run, not the raw
    // (possibly AUTO) caller request, so plan->requested_mode is truthful.
    auto plan_result = _exec_make_plan(bundle,
                                       selector,
                                       argv,
                                       env,
                                       inherit_env,
                                       strict_selector,
                                       selected,
                                       policy_mode,
                                       allocator);

    if (n00b_result_is_err(plan_result)) {
        if (n00b_result_is_err_payload(n00b_obj_bundle_error_t *,
                                       plan_result)) {
            return EXEC_RUN_ERR(
                n00b_obj_bundle_exec_result_t *,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            plan_result));
        }

        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED,
                        r"object bundle: execution planning failed",
                        mode,
                        nullptr,
                        allocator));
    }

    n00b_obj_bundle_exec_plan_t *plan = n00b_result_get(plan_result);

    // No `default`: every enum member is cased explicitly so that adding a new
    // exec mode triggers a -Wswitch diagnostic here (plan Phase 1 step 1).
    switch (selected) {
    case N00B_OBJ_BUNDLE_EXEC_EXTRACTED:
        return _exec_via_extraction(bundle,
                                    plan,
                                    fork_and_wait,
                                    fallback_used,
                                    allocator);
    case N00B_OBJ_BUNDLE_EXEC_NFS:
#if defined(__MACH__)
        // macOS-only in-memory loopback NFS mode (Phase 2).
        return _exec_via_nfs(bundle,
                             plan,
                             fork_and_wait,
                             fallback_used,
                             allocator);
#else
        // NFS is macOS-only; the probe never selects it elsewhere, so this is
        // unreachable defensively on non-darwin platforms.
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_NO_MODE_AVAILABLE,
                        r"object bundle: NFS execution mode is macOS-only",
                        selected,
                        nullptr,
                        allocator));
#endif
    case N00B_OBJ_BUNDLE_EXEC_MEMFD:
#if defined(__linux__)
        // Linux-only in-memory anonymous-fd execution mode (Phase 3).
        return _exec_via_memfd(bundle,
                               plan,
                               fork_and_wait,
                               fallback_used,
                               allocator);
#else
        // memfd is Linux-only; the probe never selects it elsewhere, so this is
        // unreachable defensively on non-Linux platforms.
        return EXEC_RUN_ERR(
            n00b_obj_bundle_exec_result_t *,
            _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_NO_MODE_AVAILABLE,
                        r"object bundle: memfd execution mode is Linux-only",
                        selected,
                        nullptr,
                        allocator));
#endif
    case N00B_OBJ_BUNDLE_EXEC_AUTO:
    case N00B_OBJ_BUNDLE_EXEC_HOST_ENTRYPOINT:
        // AUTO is resolved away by the sentinel check above; HOST_ENTRYPOINT is
        // not a runner-launch mode. Neither is launchable here — fall through to
        // the no-mode-available result below.
        break;
    }

    return EXEC_RUN_ERR(
        n00b_obj_bundle_exec_result_t *,
        _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_NO_MODE_AVAILABLE,
                    r"object bundle: no execution mode available",
                    selected,
                    nullptr,
                    allocator));
}

// ----------------------------------------------------------------------------
// Public entry points.
// ----------------------------------------------------------------------------

n00b_result_t(bool)
n00b_obj_bundle_exec_run(n00b_obj_bundle_t *bundle) _kargs
{
    n00b_string_t                *selector = nullptr;
    n00b_obj_bundle_exec_argv_t  *argv = nullptr;
    n00b_obj_bundle_exec_env_t   *env = nullptr;
    bool                          inherit_env = true;
    bool                          strict_selector = false;
    n00b_obj_bundle_exec_mode_t   mode = N00B_OBJ_BUNDLE_EXEC_AUTO;
    n00b_obj_bundle_policy_mode_t policy_mode = N00B_OBJ_BUNDLE_POLICY_ENFORCE;
    bool                          allow_extraction_fallback = true;
    n00b_allocator_t             *allocator = nullptr;
}
    ensures {
        // exec-replace never returns on success; the only returned value is the
        // failure payload, so the result is always Err and result.ok is false.
        !result.is_ok || result.ok == false;
    }
{
    // exec-replace: dispatch with fork_and_wait = false. On success the process
    // image is replaced and this never returns; the only returned value is the
    // failure error payload, so the result is always an Err here.
    auto dispatched = _exec_dispatch(bundle,
                                     selector,
                                     argv,
                                     env,
                                     inherit_env,
                                     strict_selector,
                                     mode,
                                     policy_mode,
                                     allow_extraction_fallback,
                                     false,
                                     allocator);

    n00b_obj_bundle_error_t *error =
        n00b_result_is_err_payload(n00b_obj_bundle_error_t *, dispatched)
            ? n00b_result_get_err_payload(n00b_obj_bundle_error_t *, dispatched)
            : _exec_error(N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED,
                          r"object bundle: exec-replace failed",
                          mode,
                          nullptr,
                          allocator);

    return EXEC_RUN_ERR(bool, error);
}

n00b_result_t(n00b_obj_bundle_exec_result_t *)
n00b_obj_bundle_exec_spawn(n00b_obj_bundle_t *bundle) _kargs
{
    n00b_string_t                *selector = nullptr;
    n00b_obj_bundle_exec_argv_t  *argv = nullptr;
    n00b_obj_bundle_exec_env_t   *env = nullptr;
    bool                          inherit_env = true;
    bool                          strict_selector = false;
    n00b_obj_bundle_exec_mode_t   mode = N00B_OBJ_BUNDLE_EXEC_AUTO;
    n00b_obj_bundle_policy_mode_t policy_mode = N00B_OBJ_BUNDLE_POLICY_ENFORCE;
    bool                          allow_extraction_fallback = true;
    n00b_allocator_t             *allocator = nullptr;
}
    ensures {
        // On success a concrete mode was resolved and the result is populated
        // (D-028 success-guarded): never AUTO, never null.
        !result.is_ok
            || (result.ok != nullptr
                && result.ok->resolved_mode != N00B_OBJ_BUNDLE_EXEC_AUTO);
    }
{
    return _exec_dispatch(bundle,
                          selector,
                          argv,
                          env,
                          inherit_env,
                          strict_selector,
                          mode,
                          policy_mode,
                          allow_extraction_fallback,
                          true,
                          allocator);
}

// ----------------------------------------------------------------------------
// Exec-result accessors.
// ----------------------------------------------------------------------------

n00b_obj_bundle_exec_mode_t
n00b_obj_bundle_exec_result_resolved_mode(n00b_obj_bundle_exec_result_t *r)
{
    n00b_require(r != nullptr, "object bundle exec result must not be null");
    return r->resolved_mode;
}

n00b_string_t *
n00b_obj_bundle_exec_result_launched_path(n00b_obj_bundle_exec_result_t *r)
{
    n00b_require(r != nullptr, "object bundle exec result must not be null");
    return r->launched_path;
}

bool
n00b_obj_bundle_exec_result_fallback_used(n00b_obj_bundle_exec_result_t *r)
{
    n00b_require(r != nullptr, "object bundle exec result must not be null");
    return r->fallback_used;
}

int64_t
n00b_obj_bundle_exec_result_pid(n00b_obj_bundle_exec_result_t *r)
{
    n00b_require(r != nullptr, "object bundle exec result must not be null");
    return r->pid;
}

int64_t
n00b_obj_bundle_exec_result_exit_status(n00b_obj_bundle_exec_result_t *r)
{
    n00b_require(r != nullptr, "object bundle exec result must not be null");
    return r->exit_status;
}

bool
n00b_obj_bundle_exec_result_exited_normally(n00b_obj_bundle_exec_result_t *r)
{
    n00b_require(r != nullptr, "object bundle exec result must not be null");
    return r->exited_normally;
}

// WP-016 Phase 1 — always-run, host-neutral structural test for the neutral
// execute-from-bundle runner. Exercises exec_spawn (NOT exec_run, which would
// replace the test process) of the extraction-mode runner on a trivial host
// binary, the platform selection scaffold, and the disabled-mode error path.
//
// Extraction mode is available on every dev host, so the launch cases are NOT
// gated. P1-a..P1-f from the WP-016 plan.

#include "n00b.h"
#include "adt/list.h"
#include "adt/option.h"
#include "adt/result.h"
#include "compiler/objfile/obj_bundle.h"
#include "internal/compiler/objfile/obj_bundle_exec.h"
#include "core/buffer.h"
#include "core/file.h"
#include "core/runtime.h"
#include "conduit/print.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"

#define N00B_TEST_REQUIRE(expr) n00b_require((expr), #expr)

static void
require_bool_ok(n00b_result_t(bool) result)
{
    N00B_TEST_REQUIRE(n00b_result_is_ok(result));
    N00B_TEST_REQUIRE(n00b_result_get(result));
}

// Read a host binary's bytes into a fresh buffer (copy, not a borrowed slice).
static n00b_buffer_t *
read_host_binary(n00b_string_t *path)
{
    auto open_result = n00b_file_open(path,
                                      .kind     = N00B_FILE_KIND_MMAP,
                                      .populate = true);

    N00B_TEST_REQUIRE(n00b_result_is_ok(open_result));

    n00b_file_t *f    = n00b_result_get(open_result);
    int64_t      size = n00b_file_size(f);

    N00B_TEST_REQUIRE(size > 0);

    auto read_result = n00b_file_read(f, (size_t)size);

    N00B_TEST_REQUIRE(n00b_result_is_ok(read_result));

    n00b_buffer_t *slice = n00b_result_get(read_result);
    n00b_buffer_t *copy  = n00b_buffer_from_bytes(slice->data, slice->byte_len);

    n00b_file_close(f);
    return copy;
}

// Build a bundle whose default executable is a copy of a host binary.
static n00b_obj_bundle_t *
bundle_for_host_binary(n00b_string_t *host_path)
{
    auto create = n00b_obj_bundle_new();

    N00B_TEST_REQUIRE(n00b_result_is_ok(create));

    n00b_obj_bundle_t *bundle  = n00b_result_get(create);
    n00b_string_t     *logical = r"bin/default";
    n00b_buffer_t     *bytes   = read_host_binary(host_path);

    require_bool_ok(n00b_obj_bundle_add_artifact(
        bundle,
        logical,
        bytes,
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE,
        .mode = 0755));
    require_bool_ok(n00b_obj_bundle_set_default_exec(bundle, logical));

    return bundle;
}

static n00b_obj_bundle_exec_result_t *
require_spawn_ok(n00b_result_t(n00b_obj_bundle_exec_result_t *) result)
{
    N00B_TEST_REQUIRE(n00b_result_is_ok(result));

    n00b_obj_bundle_exec_result_t *r = n00b_result_get(result);

    N00B_TEST_REQUIRE(r != nullptr);
    return r;
}

static n00b_obj_bundle_error_t *
require_spawn_error(n00b_result_t(n00b_obj_bundle_exec_result_t *) result,
                    n00b_obj_bundle_error_code_t                   expected)
{
    N00B_TEST_REQUIRE(n00b_result_is_err(result));
    N00B_TEST_REQUIRE(
        n00b_result_is_err_payload(n00b_obj_bundle_error_t *, result));

    n00b_obj_bundle_error_t *error =
        n00b_result_get_err_payload(n00b_obj_bundle_error_t *, result);

    N00B_TEST_REQUIRE(n00b_obj_bundle_error_code(error) == expected);
    return error;
}

// P1-a: spawn the extraction-mode runner on a trivial host binary; assert the
// child ran and exited normally with the expected code. /usr/bin/true exits 0,
// /usr/bin/false exits 1 — both present on macOS and Linux dev hosts.
static void
test_spawn_extracted_runs_host_binary(void)
{
    n00b_obj_bundle_t *true_bundle = bundle_for_host_binary(r"/usr/bin/true");

    n00b_obj_bundle_exec_result_t *true_result =
        require_spawn_ok(n00b_obj_bundle_exec_spawn(
            true_bundle,
            .mode = N00B_OBJ_BUNDLE_EXEC_EXTRACTED));

    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_result_exited_normally(true_result));
    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_result_exit_status(true_result) == 0);

    n00b_obj_bundle_t *false_bundle = bundle_for_host_binary(r"/usr/bin/false");

    n00b_obj_bundle_exec_result_t *false_result =
        require_spawn_ok(n00b_obj_bundle_exec_spawn(
            false_bundle,
            .mode = N00B_OBJ_BUNDLE_EXEC_EXTRACTED));

    N00B_TEST_REQUIRE(
        n00b_obj_bundle_exec_result_exited_normally(false_result));
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_exec_result_exit_status(false_result) == 1);
}

// The runner's mode SELECTION is host-dependent by design (an in-memory mode
// becomes available only when the privileged setuid NFS helper is installed —
// the gated P2-a environment). These always-run cases therefore assert against
// the actual probe rather than assuming a fixed outcome: on the standard host
// (no helper) AUTO resolves to EXTRACTED and the no-mode paths hold; when NFS IS
// available they adapt (assert the NFS selection) or skip the no-mode paths
// (which can no longer hold, and exercising them would need a privileged mount).
// This keeps the runner's own selection tests host-neutral (D-006).
static bool
nfs_available(void)
{
    return _n00b_obj_bundle_exec_mode_nfs_available();
}

// P1-b: AUTO with extraction fallback on resolves to the platform-selected mode
// — NFS when the setuid helper is installed, otherwise EXTRACTED.
static void
test_select_auto_resolves_available_mode(void)
{
    n00b_obj_bundle_exec_mode_t selected =
        _n00b_obj_bundle_exec_select_mode(N00B_OBJ_BUNDLE_EXEC_AUTO, true);

    if (nfs_available()) {
        N00B_TEST_REQUIRE(selected == N00B_OBJ_BUNDLE_EXEC_NFS);
    }
    else {
        N00B_TEST_REQUIRE(selected == N00B_OBJ_BUNDLE_EXEC_EXTRACTED);
    }
}

// P1-c: AUTO with extraction fallback OFF and no in-memory mode available →
// Err(EXEC_NO_MODE_AVAILABLE). Only holds without an in-memory mode; skip when
// NFS is available (a mode exists, so the no-mode path cannot be reached and
// exercising it would attempt a privileged mount).
static void
test_spawn_auto_no_fallback_no_mode(void)
{
    if (nfs_available()) {
        n00b_eprintf("  [P1-c SKIP] NFS available (setuid helper installed); "
                     "the no-mode-available path only holds without an "
                     "in-memory mode");
        return;
    }

    n00b_obj_bundle_t *bundle = bundle_for_host_binary(r"/usr/bin/true");

    require_spawn_error(
        n00b_obj_bundle_exec_spawn(bundle,
                                   .mode = N00B_OBJ_BUNDLE_EXEC_AUTO,
                                   .allow_extraction_fallback = false),
        N00B_OBJ_BUNDLE_ERR_EXEC_NO_MODE_AVAILABLE);
}

// P1-d: NFS requested where NFS is unavailable, fallback off →
// Err(EXEC_NO_MODE_AVAILABLE). When NFS IS available the request would attempt a
// privileged mount, so skip (the gated P2-a covers the available path).
static void
test_spawn_nfs_unavailable_no_fallback(void)
{
    if (nfs_available()) {
        n00b_eprintf("  [P1-d SKIP] NFS available (setuid helper installed); "
                     "the NFS-unavailable path is covered only without the "
                     "helper");
        return;
    }

    n00b_obj_bundle_t *bundle = bundle_for_host_binary(r"/usr/bin/true");

    require_spawn_error(
        n00b_obj_bundle_exec_spawn(bundle,
                                   .mode = N00B_OBJ_BUNDLE_EXEC_NFS,
                                   .allow_extraction_fallback = false),
        N00B_OBJ_BUNDLE_ERR_EXEC_NO_MODE_AVAILABLE);
}

// P1-e: null bundle → Err(INVALID_ARGUMENT) (D-031 body guard).
static void
test_spawn_null_bundle(void)
{
    require_spawn_error(n00b_obj_bundle_exec_spawn(nullptr),
                        N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);
}

// P1-f: resolved-mode accessor on a spawn result reports EXTRACTED.
static void
test_result_resolved_mode_extracted(void)
{
    n00b_obj_bundle_t *bundle = bundle_for_host_binary(r"/usr/bin/true");

    n00b_obj_bundle_exec_result_t *result =
        require_spawn_ok(n00b_obj_bundle_exec_spawn(
            bundle,
            .mode = N00B_OBJ_BUNDLE_EXEC_EXTRACTED));

    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_result_resolved_mode(result)
                      == N00B_OBJ_BUNDLE_EXEC_EXTRACTED);

    auto launched = n00b_obj_bundle_exec_result_launched_path(result);

    N00B_TEST_REQUIRE(launched != nullptr);
    N00B_TEST_REQUIRE(n00b_unicode_str_eq(launched, r"bin/default"));
    N00B_TEST_REQUIRE(
        !n00b_obj_bundle_exec_result_fallback_used(result));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_spawn_extracted_runs_host_binary();
    test_select_auto_resolves_available_mode();
    test_spawn_auto_no_fallback_no_mode();
    test_spawn_nfs_unavailable_no_fallback();
    test_spawn_null_bundle();
    test_result_resolved_mode_extracted();

    return 0;
}

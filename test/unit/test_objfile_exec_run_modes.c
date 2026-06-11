/**
 * @file test_objfile_exec_run_modes.c
 * @brief WP-016 gated per-mode execute-from-bundle execution test.
 *
 * Phase 2 covers the macOS-only NFS execution mode; Phase 3 adds the Linux-only
 * memfd execution mode. Mirrors the gating idiom of test_objfile_macho_oracle.c
 * (D-006 / OQ-4): the always-run unit suite stays host-neutral and
 * deterministic, while the privileged end-to-end execution cases run only behind
 * an explicit env gate + a runtime privilege/platform check and `[SKIP]` (never
 * silently pass) when the gate/platform/privilege is absent.
 *
 *   - P2-a: gated (N00B_TEST_EXEC_RUN=1 + macOS + root) — serve a real binary
 *           from memory over loopback NFS via exec_spawn(.mode=NFS) and assert
 *           the observed child exit; nothing is written to disk.
 *   - P2-b: always-run — NFS unavailable (no installed setuid helper / Linux)
 *           => the selection helper does not pick NFS.
 *   - P2-c: always-run, macOS — the setuid mount helper rejects bad/extra argv
 *           with a nonzero exit and performs NO mount.
 *   - P2-d: gate unset => `[SKIP] N00B_TEST_EXEC_RUN!=1`, exit 0.
 *   - P2-e: non-macOS => `[SKIP] NFS is macOS-only`, exit 0.
 *   - P3-a: gated (N00B_TEST_EXEC_RUN=1 + Linux, via the Docker path) — run a
 *           real binary from an anonymous memfd via exec_spawn(.mode=MEMFD) and
 *           assert the observed child exit.
 *   - P3-b: always-run, macOS — `_exec_mode_memfd_available` is false (the memfd
 *           arm is #if-compiled OUT).
 *   - P3-c: always-run, Linux — `_exec_mode_memfd_available` is true.
 *   - P3-d: non-Linux => the MEMFD execution case `[SKIP]`s, exit 0.
 *
 * D-018 test-fixture-scaffolding libc exemption: this harness/process file uses
 * getenv/printf/fork/exec/waitpid/geteuid for harness + process work; covered by
 * the n00b-api-guidelines §1 exemption. All n00b_* runner calls use the n00b
 * surface.
 */

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/runtime.h"

#if defined(_WIN32)

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("  [SKIP] objfile_exec_run_modes is POSIX-only.\n");
    return 0;
}

#else

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "adt/option.h"
#include "adt/result.h"
#include "core/buffer.h"
#include "core/file.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "compiler/objfile/obj_bundle.h"
#include "internal/compiler/objfile/obj_bundle_exec.h"

#define N00B_TEST_REQUIRE(expr) n00b_require((expr), #expr)

static bool
env_is_one(const char *name)
{
    const char *value = getenv(name);
    return value != nullptr && strcmp(value, "1") == 0;
}

static bool
file_exists(const char *path)
{
    struct stat st;
    return path != nullptr && path[0] != '\0' && stat(path, &st) == 0;
}

// Run argv to completion, returning its exit status (or 127/128 on
// spawn/abnormal exit).
static int
run_to_exit(char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) {
        return 127;
    }
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        return 127;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return 128;
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

    auto add = n00b_obj_bundle_add_artifact(
        bundle,
        logical,
        bytes,
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE,
        .mode = 0755);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add));

    auto set = n00b_obj_bundle_set_default_exec(bundle, logical);
    N00B_TEST_REQUIRE(n00b_result_is_ok(set));

    return bundle;
}

// P2-b (always-run): mode selection must stay consistent with the real host NFS
// availability. On a normal host (no installed setuid helper, or Linux) the NFS
// probe is false, so requesting NFS resolves to the "nothing available" sentinel
// (AUTO) with fallback off and to extraction with fallback on. On a privileged
// host where the helper IS installed (the P2-a environment) the probe is true,
// so requesting NFS resolves to NFS in both cases. Asserting against the probe
// (rather than assuming unavailability) keeps this always-run case correct in
// both environments.
static void
test_nfs_selection_matches_availability(void)
{
    bool nfs_available = _n00b_obj_bundle_exec_mode_nfs_available();

    n00b_obj_bundle_exec_mode_t no_fallback =
        _n00b_obj_bundle_exec_select_mode(N00B_OBJ_BUNDLE_EXEC_NFS, false);
    n00b_obj_bundle_exec_mode_t with_fallback =
        _n00b_obj_bundle_exec_select_mode(N00B_OBJ_BUNDLE_EXEC_NFS, true);

    if (nfs_available) {
        N00B_TEST_REQUIRE(no_fallback == N00B_OBJ_BUNDLE_EXEC_NFS);
        N00B_TEST_REQUIRE(with_fallback == N00B_OBJ_BUNDLE_EXEC_NFS);
    }
    else {
        N00B_TEST_REQUIRE(no_fallback == N00B_OBJ_BUNDLE_EXEC_AUTO);
        N00B_TEST_REQUIRE(with_fallback == N00B_OBJ_BUNDLE_EXEC_EXTRACTED);
    }
}

// P3-b / P3-c (always-run): the memfd probe reports availability per platform —
// true on Linux (the memfd arm is compiled in), false on macOS/other (the arm is
// #if-compiled out). Asserting per-platform keeps this case correct on both the
// Docker Linux host and the macOS dev host.
static void
test_memfd_availability_matches_platform(void)
{
    bool memfd_available = _n00b_obj_bundle_exec_mode_memfd_available();

#if defined(__linux__)
    N00B_TEST_REQUIRE(memfd_available == true);
#else
    N00B_TEST_REQUIRE(memfd_available == false);
#endif
}

#if defined(__linux__)
// P3-a (gated): run /bin/true from an anonymous memfd via exec_spawn(.mode=MEMFD)
// and assert the observed child exit. Linux-only; reached only behind the
// N00B_TEST_EXEC_RUN gate (the existing Docker path).
static void
test_memfd_spawn_from_memory(void)
{
    if (_n00b_obj_bundle_exec_select_mode(N00B_OBJ_BUNDLE_EXEC_MEMFD, false)
        != N00B_OBJ_BUNDLE_EXEC_MEMFD) {
        printf("  [SKIP] P3-a: memfd unavailable on this host\n");
        return;
    }

    n00b_string_t *host_path =
        file_exists("/bin/true") ? r"/bin/true" : r"/usr/bin/true";

    n00b_obj_bundle_t *bundle = bundle_for_host_binary(host_path);

    auto result = n00b_obj_bundle_exec_spawn(bundle,
                                             .mode = N00B_OBJ_BUNDLE_EXEC_MEMFD);

    N00B_TEST_REQUIRE(n00b_result_is_ok(result));

    n00b_obj_bundle_exec_result_t *r = n00b_result_get(result);

    N00B_TEST_REQUIRE(r != nullptr);
    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_result_resolved_mode(r)
                      == N00B_OBJ_BUNDLE_EXEC_MEMFD);
    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_result_exited_normally(r));
    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_result_exit_status(r) == 0);
}
#endif // __linux__

#if defined(__APPLE__)
// P2-c (always-run, macOS): the setuid mount helper rejects bad/extra argv with
// a nonzero exit and performs NO mount. Locates the built helper via the build
// path env var; skips (not fails) if the helper binary is not locatable.
static void
test_helper_argv_validation(void)
{
    const char *helper = getenv("N00B_NFS_MOUNT_HELPER_BUILD_PATH");

    if (!file_exists(helper)) {
        printf("  [SKIP] P2-c: mount helper binary not locatable "
               "(N00B_NFS_MOUNT_HELPER_BUILD_PATH unset/missing)\n");
        return;
    }

    // No args -> reject (nonzero), no mount.
    char *no_args[] = {(char *)helper, nullptr};
    N00B_TEST_REQUIRE(run_to_exit(no_args) != 0);

    // One arg (missing mount point) -> reject.
    char *one_arg[] = {(char *)helper, (char *)"20049", nullptr};
    N00B_TEST_REQUIRE(run_to_exit(one_arg) != 0);

    // Extra args -> reject.
    char *extra[] = {
        (char *)helper,
        (char *)"20049",
        (char *)"/tmp/n00b_helper_test_mnt",
        (char *)"extra",
        nullptr,
    };
    N00B_TEST_REQUIRE(run_to_exit(extra) != 0);

    // Non-numeric port -> reject.
    char *bad_port[] = {
        (char *)helper,
        (char *)"not-a-port",
        (char *)"/tmp/n00b_helper_test_mnt",
        nullptr,
    };
    N00B_TEST_REQUIRE(run_to_exit(bad_port) != 0);

    // Relative mount point -> reject.
    char *rel_mnt[] = {
        (char *)helper,
        (char *)"20049",
        (char *)"relative/mnt",
        nullptr,
    };
    N00B_TEST_REQUIRE(run_to_exit(rel_mnt) != 0);
}

// P2-a (gated): serve /usr/bin/true from memory over loopback NFS and assert
// the observed child exit. Requires root to mount; [SKIP]s without privilege.
static void
test_nfs_spawn_from_memory(void)
{
    if (geteuid() != 0) {
        printf("  [SKIP] P2-a: NFS mount requires root; re-run under sudo\n");
        return;
    }

    if (_n00b_obj_bundle_exec_select_mode(N00B_OBJ_BUNDLE_EXEC_NFS, false)
        != N00B_OBJ_BUNDLE_EXEC_NFS) {
        printf("  [SKIP] P2-a: NFS unavailable (setuid mount helper not "
               "installed at the fixed path)\n");
        return;
    }

    n00b_obj_bundle_t *bundle = bundle_for_host_binary(r"/usr/bin/true");

    auto result = n00b_obj_bundle_exec_spawn(bundle,
                                             .mode = N00B_OBJ_BUNDLE_EXEC_NFS);

    N00B_TEST_REQUIRE(n00b_result_is_ok(result));

    n00b_obj_bundle_exec_result_t *r = n00b_result_get(result);

    N00B_TEST_REQUIRE(r != nullptr);
    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_result_resolved_mode(r)
                      == N00B_OBJ_BUNDLE_EXEC_NFS);
    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_result_exited_normally(r));
    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_result_exit_status(r) == 0);
}
#endif // __APPLE__

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    // Always-run, host-neutral: mode selection stays consistent with the real
    // host NFS availability (P2-b) and the memfd probe matches the platform
    // (P3-b on macOS, P3-c on Linux).
    test_nfs_selection_matches_availability();
    test_memfd_availability_matches_platform();

    bool gated = env_is_one("N00B_TEST_EXEC_RUN");

#if defined(__APPLE__)
    // P2-c: helper argv validation (always-run on macOS, no env gate).
    test_helper_argv_validation();

    if (!gated) {
        // P2-d: the privileged end-to-end execution case is env-gated.
        printf("  [SKIP] N00B_TEST_EXEC_RUN!=1\n");
        return 0;
    }

    // P2-a: gated end-to-end NFS serve+mount+exec from memory.
    test_nfs_spawn_from_memory();
    // P3-d: memfd is Linux-only.
    printf("  [SKIP] memfd is Linux-only\n");
    return 0;
#elif defined(__linux__)
    // P2-e: NFS is macOS-only.
    printf("  [SKIP] NFS is macOS-only\n");

    if (!gated) {
        // P3-a is env-gated (the existing Docker path).
        printf("  [SKIP] N00B_TEST_EXEC_RUN!=1\n");
        return 0;
    }

    // P3-a: gated end-to-end memfd serve+exec from an anonymous fd.
    test_memfd_spawn_from_memory();
    return 0;
#else
    // P2-e / P3-d: neither NFS (macOS-only) nor memfd (Linux-only) is available.
    (void)gated;
    printf("  [SKIP] NFS is macOS-only\n");
    printf("  [SKIP] memfd is Linux-only\n");
    return 0;
#endif
}

#endif // _WIN32

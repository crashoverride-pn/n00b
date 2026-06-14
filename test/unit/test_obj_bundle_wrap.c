/**
 * @file test_obj_bundle_wrap.c
 * @brief WP-017 tests: the EMBEDDED_N00B program-policy backend + generic wrap.
 *
 * Grows phase by phase (see the WP-017 plan test matrix):
 *   - Phase 1 (this commit): the `n00b_exec` image-replacement primitive.
 *       - P1-a: always-run, host-neutral — fork a child, the child calls
 *               `n00b_exec(/usr/bin/true)`, the parent waits and observes exit 0
 *               (fork-then-exec, the obj_bundle_exec_run / n00b_subproc precedent;
 *               a real exec replaces only the forked child, never the test).
 *       - P1-b: always-run, host-neutral — `n00b_exec` of a nonexistent path
 *               returns Err in-process (no fork needed: exec* fails and returns).
 *       - P1-c: always-run, host-neutral — the plain-C `n00b_exec_shim` of a
 *               nonexistent path returns a nonzero error code (exercises the FFI
 *               ABI shim).
 *   - Phase 2: `_n00b_obj_bundle_vfs_from_bundle` — bundle artifacts as a VFS.
 *       - P2-a: always-run — a multi-artifact bundle (bin/a, bin/b, data/x) is
 *               exposed in the VFS; each file reads back byte-equal and the parent
 *               directories (/bin, /data) exist as directories.
 *       - P2-b: always-run — edge logical paths (single-component + deeply nested)
 *               are readable, with all intermediate directories created.
 *   - Phase 3: `_n00b_obj_bundle_run_wrapped` — compile+run the EMBEDDED_N00B
 *               policy as a full n00b PROGRAM (D-052: facts + exec; FFI accessors).
 *       - P3-a: always-run, host-neutral — a policy program returning `0` / `1`
 *               (no exec) ⇒ run-wrapped returns Ok with that int64 verdict.
 *       - P3-c: always-run — a bundle with no EMBEDDED_N00B policy ⇒ Err.
 *       - P3-b: gated (N00B_TEST_EXEC_RUN), TERMINAL — a policy program that calls the
 *               `exec_target()` FFI shim execs the embedded target via exec-REPLACE in
 *               the MAIN process (NOT forked: forking the multithreaded runtime then
 *               JIT'ing in the child deadlocks), so the test process becomes the target
 *               (exit 0). Returns only when skipped.
 *
 * D-018 test-fixture-scaffolding libc exemption: this harness/process file uses
 * getenv/printf/fork/exec/waitpid/stat/memcmp for harness + process work, covered
 * by the n00b-api-guidelines § 1 exemption. All n00b_* surface calls use the n00b
 * API.
 */

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

    printf("  [SKIP] obj_bundle_wrap is POSIX-only.\n");
    return 0;
}

#else

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "adt/array.h"
#include "adt/list.h"
#include "adt/result.h"
#include "core/buffer.h"
#include "core/env.h"
#include "core/file.h"
#include "core/string.h"
#include "util/assert.h"
#include "util/exec.h"
#include "util/path.h"
#include "util/proc.h"
#include "util/wrap_policy.h"
#include "vfs/vfs.h"
#include "vfs/types.h"
#include "compiler/objfile/obj_bundle.h"
#include "internal/compiler/objfile/obj_bundle_exec.h"

#define N00B_TEST_REQUIRE(expr) n00b_require((expr), #expr)

static bool
file_exists(const char *path)
{
    struct stat st;
    return path != nullptr && path[0] != '\0' && stat(path, &st) == 0;
}

// P1-a: fork-then-exec. The child replaces its image with /usr/bin/true (exit
// 0); the parent observes the child's exit status. n00b_exec is exercised on its
// success path (which never returns in the child).
static void
test_exec_replaces_child(void)
{
    bool           have_bin = file_exists("/bin/true");
    bool           have_usr = file_exists("/usr/bin/true");
    n00b_string_t *true_path;

    if (have_bin) {
        true_path = r"/bin/true";
    }
    else if (have_usr) {
        true_path = r"/usr/bin/true";
    }
    else {
        printf("  [SKIP] P1-a: no /bin/true or /usr/bin/true present\n");
        return;
    }

    pid_t pid = fork();
    N00B_TEST_REQUIRE(pid >= 0);

    if (pid == 0) {
        // Child: replace this image. n00b_exec returns ONLY on failure.
        n00b_exec(true_path);
        _exit(127);
    }

    int status = 0;
    N00B_TEST_REQUIRE(waitpid(pid, &status, 0) == pid);
    N00B_TEST_REQUIRE(WIFEXITED(status));
    N00B_TEST_REQUIRE(WEXITSTATUS(status) == 0);
}

// P1-b: failure path. exec* of a nonexistent path fails and returns; n00b_exec
// surfaces an Err. Safe to run in-process (no image replacement occurs).
static void
test_exec_failure_returns_err(void)
{
    auto result = n00b_exec(r"/n00b/no/such/executable/path");

    N00B_TEST_REQUIRE(n00b_result_is_err(result));
    N00B_TEST_REQUIRE(n00b_result_get_err(result)
                      == N00B_EXEC_ERR_LAUNCH_FAILED);
}

// P1-c: the plain-C FFI shim's failure path returns a nonzero error code.
static void
test_exec_shim_failure_nonzero(void)
{
    const char *argv[] = {"/n00b/no/such/executable/path", nullptr};
    int64_t     rc     = n00b_exec_shim("/n00b/no/such/executable/path", argv);

    N00B_TEST_REQUIRE(rc != 0);
    N00B_TEST_REQUIRE(rc == N00B_EXEC_ERR_LAUNCH_FAILED);
}

// ---------------------------------------------------------------------------
// Phase 2 helpers + tests: _n00b_obj_bundle_vfs_from_bundle
// ---------------------------------------------------------------------------

static n00b_buffer_t *
buf_of(const char *s)
{
    return n00b_buffer_from_bytes((char *)s, (int64_t)strlen(s));
}

static void
add_file(n00b_obj_bundle_t *bundle, n00b_string_t *logical, const char *contents)
{
    auto add = n00b_obj_bundle_add_artifact(bundle,
                                            logical,
                                            buf_of(contents),
                                            .kind = N00B_OBJ_BUNDLE_ARTIFACT_FILE,
                                            .mode = 0644);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add));
}

// Open vpath read-only, read its bytes, and assert they equal `expected`.
static void
require_file_bytes(n00b_vfs_t *vfs, n00b_string_t *vpath, const char *expected)
{
    auto open_result = n00b_vfs_open(vfs, vpath, N00B_VFS_O_R);
    N00B_TEST_REQUIRE(n00b_result_is_ok(open_result));

    n00b_vfs_fh_t fh        = n00b_result_get(open_result);
    size_t        exp_len   = strlen(expected);
    auto          read_result = n00b_vfs_read(vfs, fh, (uint64_t)exp_len + 16);
    N00B_TEST_REQUIRE(n00b_result_is_ok(read_result));

    n00b_buffer_t *got = n00b_result_get(read_result);
    N00B_TEST_REQUIRE(got != nullptr);
    N00B_TEST_REQUIRE((size_t)got->byte_len == exp_len);
    N00B_TEST_REQUIRE(memcmp(got->data, expected, exp_len) == 0);

    n00b_vfs_close(vfs, fh);
}

static void
require_is_dir(n00b_vfs_t *vfs, n00b_string_t *vpath)
{
    auto st = n00b_vfs_stat(vfs, vpath);
    N00B_TEST_REQUIRE(n00b_result_is_ok(st));
    n00b_vfs_obj_stat_t info = n00b_result_get(st);
    N00B_TEST_REQUIRE(info.kind == N00B_VFS_OBJ_DIR);
}

// P2-a: a multi-artifact bundle exposes every artifact in the VFS byte-equal,
// with intermediate directories present.
static void
test_vfs_from_bundle_multi(void)
{
    auto create = n00b_obj_bundle_new();
    N00B_TEST_REQUIRE(n00b_result_is_ok(create));
    n00b_obj_bundle_t *bundle = n00b_result_get(create);

    add_file(bundle, r"bin/a", "AAAA-alpha");
    add_file(bundle, r"bin/b", "B");
    add_file(bundle, r"data/x", "xyz-123-data");

    auto vfs_result = _n00b_obj_bundle_vfs_from_bundle(bundle);
    N00B_TEST_REQUIRE(n00b_result_is_ok(vfs_result));
    n00b_vfs_t *vfs = n00b_result_get(vfs_result);

    require_file_bytes(vfs, r"/bin/a", "AAAA-alpha");
    require_file_bytes(vfs, r"/bin/b", "B");
    require_file_bytes(vfs, r"/data/x", "xyz-123-data");

    require_is_dir(vfs, r"/bin");
    require_is_dir(vfs, r"/data");

    n00b_vfs_destroy(vfs);
}

// P2-b: edge logical paths — a single-component file and a deeply nested file,
// with all intermediate directories created.
static void
test_vfs_from_bundle_edge_paths(void)
{
    auto create = n00b_obj_bundle_new();
    N00B_TEST_REQUIRE(n00b_result_is_ok(create));
    n00b_obj_bundle_t *bundle = n00b_result_get(create);

    add_file(bundle, r"top", "root-level");
    add_file(bundle, r"a/b/c/leaf", "deeply-nested");

    auto vfs_result = _n00b_obj_bundle_vfs_from_bundle(bundle);
    N00B_TEST_REQUIRE(n00b_result_is_ok(vfs_result));
    n00b_vfs_t *vfs = n00b_result_get(vfs_result);

    require_file_bytes(vfs, r"/top", "root-level");
    require_file_bytes(vfs, r"/a/b/c/leaf", "deeply-nested");

    require_is_dir(vfs, r"/a");
    require_is_dir(vfs, r"/a/b");
    require_is_dir(vfs, r"/a/b/c");

    n00b_vfs_destroy(vfs);
}

// P2 (negative, host-neutral): a null bundle is a body-guarded Err.
static void
test_vfs_from_bundle_null(void)
{
    auto vfs_result = _n00b_obj_bundle_vfs_from_bundle(nullptr);
    N00B_TEST_REQUIRE(n00b_result_is_err(vfs_result));
}

// ---------------------------------------------------------------------------
// Phase 3 helpers + tests: _n00b_obj_bundle_run_wrapped
// ---------------------------------------------------------------------------

#define TEST_EMBEDDED_POLICY_COMPAT_FLAGS_OFF 16u
#define TEST_EMBEDDED_POLICY_FALLBACK_ID_OFF  24u
#define TEST_EMBEDDED_POLICY_SOURCE_LEN_OFF   32u

static bool
env_is_one(const char *name)
{
    const char *value = getenv(name);
    return value != nullptr && strcmp(value, "1") == 0;
}

// Whether the in-process EMBEDDED_N00B policy PROGRAM path (which brings up an
// eval session and JIT-compiles via MIR) can run here. Off-macOS the MIR-JIT
// codegen hangs during eval-session bringup (n00b_eval_session_new →
// load_builtins → generate_func_code) in our validated environments — Linux/arm64
// confirmed, and the plain test_n00b_eval hangs identically. That is the
// in-progress MIR-JIT / interpreter bring-up, NOT the object-bundle wrap path:
// the no-extract exec mechanism itself is proven on Linux by objfile_exec_run_modes
// (memfd) and end-to-end on macOS. JIT-dependent tests SKIP (never hang) where the
// JIT is non-functional; set N00B_TEST_EVAL_JIT=1 to force-run them where the JIT
// is known good. See WP-018 in the wp-017 phase-log.
static bool
eval_jit_supported(void)
{
#if defined(__APPLE__)
    return true;
#else
    return env_is_one("N00B_TEST_EVAL_JIT");
#endif
}

static void
write_le16(uint8_t *data, size_t off, uint16_t value)
{
    data[off]     = (uint8_t)value;
    data[off + 1] = (uint8_t)(value >> 8);
}

static void
write_le32(uint8_t *data, size_t off, uint32_t value)
{
    data[off]     = (uint8_t)value;
    data[off + 1] = (uint8_t)(value >> 8);
    data[off + 2] = (uint8_t)(value >> 16);
    data[off + 3] = (uint8_t)(value >> 24);
}

static void
write_le64(uint8_t *data, size_t off, uint64_t value)
{
    write_le32(data, off, (uint32_t)value);
    write_le32(data, off + 4, (uint32_t)(value >> 32));
}

// Build a canonical v1 EMBEDDED_N00B policy payload envelope around `source`
// (mirrors test_objfile_obj_bundle_policy.c's helper).
static n00b_buffer_t *
make_embedded_policy_payload(uint64_t fallback_policy_id, n00b_string_t *source)
{
    size_t len = N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SOURCE_OFF + source->u8_bytes;
    n00b_buffer_t *payload = n00b_buffer_new((int64_t)len);
    uint8_t       *data    = (uint8_t *)payload->data;

    for (size_t i = 0; i < len; i++) {
        data[i] = 0;
    }

    memcpy(data,
           N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAGIC,
           N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAGIC_LEN);
    write_le16(data, 8, N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAJOR);
    write_le16(data, 10, N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MINOR);
    write_le64(data,
               TEST_EMBEDDED_POLICY_COMPAT_FLAGS_OFF,
               N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SUPPORTED_COMPAT_FLAGS);
    write_le64(data, TEST_EMBEDDED_POLICY_FALLBACK_ID_OFF, fallback_policy_id);
    write_le64(data, TEST_EMBEDDED_POLICY_SOURCE_LEN_OFF, source->u8_bytes);
    memcpy(data + N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SOURCE_OFF,
           source->data,
           source->u8_bytes);

    return payload;
}

// A fresh bundle carrying an EMBEDDED_N00B EXECUTION policy whose program is
// `policy_source`.
static n00b_obj_bundle_t *
bundle_with_policy(n00b_string_t *policy_source)
{
    auto create = n00b_obj_bundle_new();
    N00B_TEST_REQUIRE(n00b_result_is_ok(create));
    n00b_obj_bundle_t *bundle = n00b_result_get(create);

    n00b_buffer_t *payload =
        make_embedded_policy_payload(N00B_OBJ_BUNDLE_POLICY_ID_NONE,
                                     policy_source);

    auto add = n00b_obj_bundle_add_policy(
        bundle,
        1,
        N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
        .payload = payload);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add));

    return bundle;
}

// P3-a: a policy program that just evaluates to an int64 verdict (no exec) ⇒
// run-wrapped returns Ok carrying that verdict.
static void
test_run_wrapped_verdict(void)
{
    if (!eval_jit_supported()) {
        printf("  [SKIP] P3-a: eval JIT bringup hangs off-macOS "
               "(MIR-JIT bring-up; set N00B_TEST_EVAL_JIT=1 to force)\n");
        return;
    }

    auto allow = _n00b_obj_bundle_run_wrapped(bundle_with_policy(r"0"));
    N00B_TEST_REQUIRE(n00b_result_is_ok(allow));
    N00B_TEST_REQUIRE(n00b_result_get(allow) == 0);

    auto deny = _n00b_obj_bundle_run_wrapped(bundle_with_policy(r"1"));
    N00B_TEST_REQUIRE(n00b_result_is_ok(deny));
    N00B_TEST_REQUIRE(n00b_result_get(deny) == 1);

    printf("  P3-a: run-wrapped verdict (0/1) OK\n");
}

// P3-c: a bundle with no EMBEDDED_N00B policy ⇒ Err (also the null-bundle case).
static void
test_run_wrapped_no_policy(void)
{
    auto create = n00b_obj_bundle_new();
    N00B_TEST_REQUIRE(n00b_result_is_ok(create));
    n00b_obj_bundle_t *bundle = n00b_result_get(create);

    auto r = _n00b_obj_bundle_run_wrapped(bundle);
    N00B_TEST_REQUIRE(n00b_result_is_err(r));

    auto rn = _n00b_obj_bundle_run_wrapped(nullptr);
    N00B_TEST_REQUIRE(n00b_result_is_err(rn));
}

// Read a host binary's bytes into a fresh buffer (copy).
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
    n00b_buffer_t *copy  = n00b_buffer_from_bytes(slice->data,
                                                  (int64_t)slice->byte_len);

    n00b_file_close(f);
    return copy;
}

// P3-b (gated): the policy program execs the embedded target. exec_target() is
// exec-REPLACE, so this is the test's TERMINAL action in the MAIN process: on
// success this process becomes /bin/true (exit 0). It is NOT forked — forking the
// multithreaded n00b runtime and then doing JIT work (eval_session_new) in the
// child deadlocks on locks held by non-forked threads. Returns only when SKIPPED
// (not gated / no binary); on a real run it execs (never returns) or _exit(1)s.
static void
maybe_exec_target_gated(void)
{
    if (!env_is_one("N00B_TEST_EXEC_RUN")) {
        printf("  [SKIP] P3-b: N00B_TEST_EXEC_RUN!=1\n");
        return;
    }

    if (!eval_jit_supported()) {
        printf("  [SKIP] P3-b: eval JIT bringup hangs off-macOS "
               "(MIR-JIT bring-up; set N00B_TEST_EVAL_JIT=1 to force)\n");
        return;
    }

    n00b_string_t *true_path =
        file_exists("/bin/true") ? r"/bin/true" : r"/usr/bin/true";
    if (!file_exists(true_path->data)) {
        printf("  [SKIP] P3-b: no /bin/true or /usr/bin/true present\n");
        return;
    }

    auto create = n00b_obj_bundle_new();
    N00B_TEST_REQUIRE(n00b_result_is_ok(create));
    n00b_obj_bundle_t *bundle  = n00b_result_get(create);
    n00b_string_t     *logical = r"bin/target";

    auto add = n00b_obj_bundle_add_artifact(bundle,
                                            logical,
                                            read_host_binary(true_path),
                                            .kind = N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE,
                                            .mode = 0755);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add));
    N00B_TEST_REQUIRE(
        n00b_result_is_ok(n00b_obj_bundle_set_default_exec(bundle, logical)));

    n00b_buffer_t *payload =
        make_embedded_policy_payload(N00B_OBJ_BUNDLE_POLICY_ID_NONE,
                                     r"exec_target()");
    N00B_TEST_REQUIRE(n00b_result_is_ok(n00b_obj_bundle_add_policy(
        bundle,
        1,
        N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
        .payload = payload)));

    // The policy program calls exec_target() → exec-replace with /bin/true. On
    // success this process becomes /bin/true and never returns here.
    printf("  P3-b: running policy that execs the embedded target...\n");
    fflush(stdout);
    _n00b_obj_bundle_run_wrapped(bundle);

    // Only reached if the exec did not happen.
    printf("  P3-b FAIL: run_wrapped returned without exec'ing\n");
    _exit(1);
}

// ---------------------------------------------------------------------------
// Phase 4 helpers + tests: n00b_obj_bundle_wrap + the agent-guard policy program
// ---------------------------------------------------------------------------

// The default agent-guard policy PROGRAM (kept byte-identical to
// src/tools/n00b_wrap.c WRAP_DEFAULT_POLICY_SOURCE — the canonical demo policy).
#define TEST_AGENT_GUARD_SOURCE                                               \
    "if caller_is_blocked_agent() != 0 {\n"                                   \
    "  eprint(\"Agent cannot directly run this command. "                     \
    "Prompt the user if you need more guidance.\")\n"                         \
    "} else {\n"                                                              \
    "  exec_target()\n"                                                       \
    "}\n"                                                                     \
    "126\n"

// Resolve the committed unsigned arm64 Mach-O fixture (the wrap carrier host).
static n00b_string_t *
fixture_macho_path(void)
{
    const char *root = getenv("MESON_SOURCE_ROOT");
    char        path[1024];
    const char *rel = "test/unit/data/hello_unsigned_arm64.macho";

    if (root != nullptr && root[0] != '\0') {
        int n = snprintf(path, sizeof(path), "%s/%s", root, rel);
        if (n > 0 && (size_t)n < sizeof(path)) {
            return n00b_string_from_cstr(path);
        }
    }

    return n00b_string_from_cstr(rel);
}

// P4-a: wrap a target into a Mach-O carrier, read it back, and assert the
// embedded artifact, default-exec, and EMBEDDED_N00B policy all round-trip.
// Mach-O wrap (write_file → ad-hoc resign) is macOS-only, so this is gated on
// __APPLE__ and skipped elsewhere (D-006).
static void
test_wrap_roundtrip(void)
{
#if !defined(__APPLE__)
    printf("  [SKIP] P4-a: Mach-O wrap is macOS-only\n");
#else
    n00b_string_t *fixture = fixture_macho_path();

    if (!file_exists(fixture->data)) {
        printf("  [SKIP] P4-a: unsigned arm64 fixture unavailable\n");
        return;
    }

    n00b_buffer_t *host = read_host_binary(fixture);

    // The carrier host doubles as the single embedded target (basename logical
    // path "hello_unsigned_arm64.macho").
    n00b_string_t *logical = r"hello_unsigned_arm64.macho";
    n00b_list_t(n00b_string_t *) *targets =
        n00b_alloc(n00b_list_t(n00b_string_t *));
    *targets = n00b_list_new(n00b_string_t *);
    n00b_list_push(*targets, fixture);

    auto td = n00b_new_temp_dir(r"n00b-wrap-test-", nullptr);
    N00B_TEST_REQUIRE(n00b_result_is_ok(td));
    n00b_string_t *out = n00b_path_simple_join(n00b_result_get(td), r"wrapped");

    auto wrapped = n00b_obj_bundle_wrap(host, targets, r"0", out);
    N00B_TEST_REQUIRE(n00b_result_is_ok(wrapped));

    // Read the wrapped output back through the neutral reader.
    n00b_buffer_t *out_bytes = read_host_binary(out);
    auto           rb        = n00b_obj_bundle_read(out_bytes);
    N00B_TEST_REQUIRE(n00b_result_is_ok(rb));
    n00b_obj_bundle_t *bundle = n00b_result_get(rb);

    // default-exec is the first target's basename.
    n00b_option_t(n00b_string_t *) de_opt =
        _n00b_obj_bundle_default_exec_logical_path(bundle);
    N00B_TEST_REQUIRE(n00b_option_is_set(de_opt));
    n00b_string_t *de = n00b_option_get(de_opt);
    N00B_TEST_REQUIRE(n00b_unicode_str_eq(de, logical));

    // The EMBEDDED_N00B EXECUTION policy round-trips with its source intact.
    n00b_option_t(n00b_string_t *) src_opt =
        _n00b_obj_bundle_embedded_policy_source_for_scope(
            bundle,
            N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION);
    N00B_TEST_REQUIRE(n00b_option_is_set(src_opt));
    n00b_string_t *src = n00b_option_get(src_opt);
    N00B_TEST_REQUIRE(n00b_unicode_str_eq(src, r"0"));

    // The embedded target bytes equal the input.
    const n00b_buffer_t *payload =
        _n00b_obj_bundle_artifact_bytes_for_path(bundle, logical);
    N00B_TEST_REQUIRE(payload != nullptr);
    N00B_TEST_REQUIRE(payload->byte_len == host->byte_len);
    N00B_TEST_REQUIRE(
        memcmp(payload->data, host->data, (size_t)host->byte_len) == 0);

    printf("  P4-a: wrap roundtrip OK\n");
#endif
}

// Build an n00b_proc_info_t for an injected ancestry chain.
static n00b_proc_info_t *
mk_proc(const char *name, const char *exe_path)
{
    n00b_proc_info_t *p = n00b_alloc(n00b_proc_info_t);

    p->pid       = 1;
    p->ppid      = 1;
    p->proc_name = (name != nullptr) ? n00b_string_from_cstr(name) : nullptr;
    p->exe_name  = (name != nullptr) ? n00b_string_from_cstr(name) : nullptr;
    p->exe_path  = (exe_path != nullptr) ? n00b_string_from_cstr(exe_path)
                                         : nullptr;
    return p;
}

// P4-c: the agent-ancestry verdict, exercised host-neutrally with INJECTED
// chains (a real agent ancestor is not reproducible in the harness). Index 0 is
// always the process itself; classification runs from index 1 upward.
static void
test_agent_verdict_injected(void)
{
    n00b_array_t(n00b_string_t *) agents =
        n00b_unicode_str_split(r"claude", r",");
    n00b_array_t(n00b_string_t *) shells =
        n00b_unicode_str_split(r"sh,bash,zsh,dash,ksh,fish,tcsh,csh", r",");

    // (1) agent reached through shells-only ⇒ BLOCK.
    n00b_list_t(n00b_proc_info_t *) c1 = n00b_list_new(n00b_proc_info_t *);
    n00b_list_push(c1, mk_proc("n00b-wrap", "/usr/local/bin/n00b-wrap"));
    n00b_list_push(c1, mk_proc("bash", "/bin/bash"));
    n00b_list_push(c1, mk_proc("claude", "/usr/local/bin/claude"));
    N00B_TEST_REQUIRE(
        n00b_wrap_ancestry_is_blocked(&c1, &agents, &shells) == true);

    // (2) a non-shell ancestor breaks the chain before the agent ⇒ ALLOW.
    n00b_list_t(n00b_proc_info_t *) c2 = n00b_list_new(n00b_proc_info_t *);
    n00b_list_push(c2, mk_proc("n00b-wrap", "/usr/local/bin/n00b-wrap"));
    n00b_list_push(c2, mk_proc("bash", "/bin/bash"));
    n00b_list_push(c2, mk_proc("jj", "/usr/local/bin/jj"));
    n00b_list_push(c2, mk_proc("claude", "/usr/local/bin/claude"));
    N00B_TEST_REQUIRE(
        n00b_wrap_ancestry_is_blocked(&c2, &agents, &shells) == false);

    // (3) a direct agent parent ⇒ BLOCK.
    n00b_list_t(n00b_proc_info_t *) c3 = n00b_list_new(n00b_proc_info_t *);
    n00b_list_push(c3, mk_proc("n00b-wrap", "/usr/local/bin/n00b-wrap"));
    n00b_list_push(c3, mk_proc("claude", "/usr/local/bin/claude"));
    N00B_TEST_REQUIRE(
        n00b_wrap_ancestry_is_blocked(&c3, &agents, &shells) == true);

    // (4) self only (no ancestors) ⇒ ALLOW.
    n00b_list_t(n00b_proc_info_t *) c4 = n00b_list_new(n00b_proc_info_t *);
    n00b_list_push(c4, mk_proc("n00b-wrap", "/usr/local/bin/n00b-wrap"));
    N00B_TEST_REQUIRE(
        n00b_wrap_ancestry_is_blocked(&c4, &agents, &shells) == false);

    // (5) a version-named agent binary matched by a PATH COMPONENT, through a
    //     shell ⇒ BLOCK (the launcher's basename is "node", but the path has a
    //     "claude" component).
    n00b_list_t(n00b_proc_info_t *) c5 = n00b_list_new(n00b_proc_info_t *);
    n00b_list_push(c5, mk_proc("n00b-wrap", "/usr/local/bin/n00b-wrap"));
    n00b_list_push(c5, mk_proc("zsh", "/bin/zsh"));
    n00b_list_push(c5,
                   mk_proc("node", "/opt/share/claude/versions/1.2.3/node"));
    N00B_TEST_REQUIRE(
        n00b_wrap_ancestry_is_blocked(&c5, &agents, &shells) == true);

    printf("  P4-c: agent-ancestry verdict (injected chains) OK\n");
}

// P5-a (WP-018, pure — runs everywhere): the policy-free direct exec plan that
// the wrap path now builds for an ALREADY-DECIDED target (the EMBEDDED_N00B
// program already ran AS the policy, so there is no predicate to evaluate).
// Assert it carries the selected logical path and the FULL passthrough argv
// INCLUDING argv[0] (some binaries dispatch on argv[0]), requests env
// inheritance, and uses no strict selector.
static void
test_exec_plan_direct_preserves_argv0(void)
{
    n00b_string_t *logical = r"bin/target";

    n00b_obj_bundle_exec_argv_t *argv = n00b_alloc(n00b_obj_bundle_exec_argv_t);
    *argv = n00b_list_new(n00b_string_t *);
    n00b_list_push(*argv, r"git"); // argv[0] — the wrapper's invocation name
    n00b_list_push(*argv, r"status");
    n00b_list_push(*argv, r"--short");

    n00b_obj_bundle_exec_plan_t *plan =
        _n00b_obj_bundle_exec_plan_direct(logical,
                                          argv,
                                          nullptr,
                                          N00B_OBJ_BUNDLE_EXEC_AUTO);
    N00B_TEST_REQUIRE(plan != nullptr);

    auto sel = n00b_obj_bundle_exec_plan_selected_logical_path(plan);
    N00B_TEST_REQUIRE(n00b_option_is_set(sel));
    N00B_TEST_REQUIRE(n00b_unicode_str_eq(n00b_option_get(sel), logical));

    auto argv_opt = n00b_obj_bundle_exec_plan_argv(plan);
    N00B_TEST_REQUIRE(n00b_option_is_set(argv_opt));
    n00b_obj_bundle_exec_argv_t *planned = n00b_option_get(argv_opt);
    N00B_TEST_REQUIRE(n00b_list_len(*planned) == 3);
    N00B_TEST_REQUIRE(n00b_unicode_str_eq(n00b_list_get(*planned, 0), r"git"));
    N00B_TEST_REQUIRE(n00b_unicode_str_eq(n00b_list_get(*planned, 1), r"status"));
    N00B_TEST_REQUIRE(
        n00b_unicode_str_eq(n00b_list_get(*planned, 2), r"--short"));

    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_plan_inherit_env(plan) == true);
    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_plan_strict_selector(plan) == false);

    printf("  P5-a: direct exec plan preserves selected path + argv[0] OK\n");
}

// P5-b (WP-018, pure — runs everywhere): the decided exec entry rejects a null
// bundle with an Err (no exec attempted). This exercises the policy-free entry's
// guard without becoming terminal (a valid bundle would exec-replace).
static void
test_exec_run_decided_null_bundle(void)
{
    n00b_obj_bundle_exec_argv_t *argv = n00b_alloc(n00b_obj_bundle_exec_argv_t);
    *argv = n00b_list_new(n00b_string_t *);
    n00b_list_push(*argv, r"target");

    auto run = _n00b_obj_bundle_exec_run_decided(nullptr, r"bin/target", argv);
    N00B_TEST_REQUIRE(n00b_result_is_err(run));

    printf("  P5-b: decided exec entry rejects null bundle OK\n");
}

// P4-b (gated): the DEFAULT agent-guard policy program on its ALLOW path execs
// the embedded target. Like P3-b this is exec-REPLACE as the test's TERMINAL
// action in the MAIN process (forking the multithreaded runtime then JIT'ing in
// the child deadlocks). N00B_WRAP_AGENTS is set to a sentinel so the verdict is
// ALLOW regardless of the real ancestry (so the test is deterministic even when
// run under an agent). On success this process becomes the target (exit 0);
// returns only when skipped.
static void
maybe_wrap_allow_path_gated(void)
{
    if (!env_is_one("N00B_TEST_EXEC_RUN")) {
        printf("  [SKIP] P4-b: N00B_TEST_EXEC_RUN!=1\n");
        return;
    }

    if (!eval_jit_supported()) {
        printf("  [SKIP] P4-b: eval JIT bringup hangs off-macOS "
               "(MIR-JIT bring-up; set N00B_TEST_EVAL_JIT=1 to force)\n");
        return;
    }

    n00b_string_t *true_path =
        file_exists("/bin/true") ? r"/bin/true" : r"/usr/bin/true";
    if (!file_exists(true_path->data)) {
        printf("  [SKIP] P4-b: no /bin/true or /usr/bin/true present\n");
        return;
    }

    // Force ALLOW regardless of the real ancestry (so the test is deterministic
    // even when run under an agent): override the agent set with a sentinel that
    // matches nothing. Use n00b_putenv — the policy shim reads n00b_getenv, which
    // sees the runtime env snapshot (a C setenv after n00b_init would be invisible).
    n00b_putenv(r"N00B_WRAP_AGENTS", r"__n00b_no_such_agent__");

    auto create = n00b_obj_bundle_new();
    N00B_TEST_REQUIRE(n00b_result_is_ok(create));
    n00b_obj_bundle_t *bundle  = n00b_result_get(create);
    n00b_string_t     *logical = r"bin/target";

    auto add = n00b_obj_bundle_add_artifact(bundle,
                                            logical,
                                            read_host_binary(true_path),
                                            .kind = N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE,
                                            .mode = 0755);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add));
    N00B_TEST_REQUIRE(
        n00b_result_is_ok(n00b_obj_bundle_set_default_exec(bundle, logical)));

    n00b_buffer_t *payload = make_embedded_policy_payload(
        N00B_OBJ_BUNDLE_POLICY_ID_NONE,
        n00b_string_from_cstr(TEST_AGENT_GUARD_SOURCE));
    N00B_TEST_REQUIRE(n00b_result_is_ok(n00b_obj_bundle_add_policy(
        bundle,
        1,
        N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
        .payload = payload)));

    printf("  P4-b: running agent-guard policy on its allow path...\n");
    fflush(stdout);
    _n00b_obj_bundle_run_wrapped(bundle);

    // Only reached if the exec did not happen (write the diagnostic to the
    // unbuffered fd 2 since _exit does not flush stdio).
    static const char fail[] =
        "  P4-b FAIL: agent-guard allow path returned without exec'ing\n";
    ssize_t ignored = write(2, fail, sizeof(fail) - 1);
    (void)ignored;
    _exit(1);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    // Phase 1: n00b_exec.
    test_exec_replaces_child();
    test_exec_failure_returns_err();
    test_exec_shim_failure_nonzero();

    // Phase 2: VFS-from-bundle.
    test_vfs_from_bundle_multi();
    test_vfs_from_bundle_edge_paths();
    test_vfs_from_bundle_null();

    // Phase 3: run the EMBEDDED_N00B policy program.
    test_run_wrapped_verdict();
    test_run_wrapped_no_policy();

    // Phase 4: wrap API + agent-guard policy program (non-terminal tests).
    test_wrap_roundtrip();
    test_agent_verdict_injected();

    // WP-018: no-extract exec path (policy-free direct plan + decided entry).
    test_exec_plan_direct_preserves_argv0();
    test_exec_run_decided_null_bundle();

    // Gated TERMINAL exec tests. Each is exec-REPLACE (never returns on a real
    // run), so they are mutually exclusive: under N00B_TEST_EXEC_RUN the first
    // one fires and the process becomes the embedded target. P4-b (the Phase-4
    // agent-guard ALLOW path) runs first — it supersedes P3-b's bare
    // exec_target() mechanism (both end by exec'ing the embedded target). Both
    // print [SKIP] when the gate is off.
    maybe_wrap_allow_path_gated();   // P4-b
    maybe_exec_target_gated();       // P3-b (subset; reached only when ungated)

    printf("  obj_bundle_wrap: Phase 1 + Phase 2 + Phase 3 + Phase 4 OK\n");
    return 0;
}

#endif // _WIN32

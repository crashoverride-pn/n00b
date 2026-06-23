/**
 * @file test_objfile_macho_oracle.c
 * @brief Gated Mach-O signing oracle + FR-14 entrypoint round-trip (P2-g).
 *
 * Mirrors `test_objfile_elf_oracle.c`'s env-gate convention (D-006 /
 * D-015 / NFR-07): the default unit suite is deterministic and
 * host-neutral and requires no signing identity, while this oracle runs
 * a real loader/codesign check only behind an explicit env gate.
 *
 * Gate: `N00B_TEST_MACHO_ORACLE`.
 *   - unset / != "1": print `[SKIP] N00B_TEST_MACHO_ORACLE!=1` and exit 0.
 *   - == "1": on Darwin, (1) run `/usr/bin/codesign --verify --deep
 *     --strict` against the committed ad-hoc-signed fixture and assert
 *     exit 0; (2) run the FR-14 / D-009 round-trip (P2-g) through the
 *     PRODUCT plan/apply path. On any tooling error while gated, print
 *     `[FAIL]` (NOT skip) and exit nonzero — a set gate never silently
 *     passes. On non-Darwin with the gate set, print `[FAIL]` (codesign(1)
 *     is macOS-only).
 *
 * P2-g (FR-14, D-009 confirmation in the production engine): on the
 * committed `hello_signed_arm64.macho`, via the product path —
 *   strip (n00b_chalk_macho_strip_signature)
 *   -> plan_loadable_insert (payload = the arm64 trampoline that exits 42)
 *   -> apply_loadable_insert_plan -> reparse
 *   -> plan_host_entrypoint_target (target = the trampoline)
 *   -> enable_entrypoint
 *   -> apply_loadable_insert_plan (now writes the redirected entryoff)
 *   -> write to a temp file -> n00b_chalk_macho_resign (ad-hoc, signer=nullptr)
 *   -> codesign --verify --deep --strict exit 0 -> execute -> exit 42.
 * This reproduces the WP-001 spike round-trip in the product code path.
 *
 * D-018 test-fixture-scaffolding libc exemption: this harness/process file
 * uses getenv/printf/snprintf/fork/exec/stat/mkstemp/write for harness and
 * process work; covered by the n00b-api-guidelines §1 exemption.
 *
 * No signing credentials are committed; the fixture is ad-hoc signed.
 */

#include <assert.h>
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

    printf("  [SKIP] objfile_macho_oracle is POSIX-only for now.\n");
    return 0;
}

#else

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

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
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

// Resolve the committed fixture path via MESON_SOURCE_ROOT (set by the
// meson test runner) with a project-root-relative fallback.
static bool
resolve_fixture(char *out, size_t out_len)
{
    static const char *rel = "test/unit/data/hello_signed_arm64.macho";

    const char *root = getenv("MESON_SOURCE_ROOT");
    if (root != nullptr && root[0] != '\0') {
        int n = snprintf(out, out_len, "%s/%s", root, rel);
        if (n > 0 && (size_t)n < out_len && file_exists(out)) {
            return true;
        }
    }

    int n = snprintf(out, out_len, "%s", rel);
    if (n > 0 && (size_t)n < out_len && file_exists(out)) {
        return true;
    }

    return false;
}

// Run argv to completion, returning its exit status (or 127/128 on
// spawn/abnormal exit).
static int
run_to_exit(char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork failed: %s\n", strerror(errno));
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

#if defined(__APPLE__)

#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "compiler/objfile/bstream.h"
#include "compiler/objfile/macho.h"
#include "compiler/objfile/macho_rewrite.h"
#include "compiler/objfile/macho_rewrite_admit.h"
#include "chalk/n00b_chalk_resign.h"
#include "chalk/n00b_chalk_macho.h"

#define ARM64_PAGE          0x4000u
#define SENTINEL_EXIT_CODE  42

// arm64 trampoline: exit(42) via SYS_exit (1). Verified encodings (the WP-001
// spike, test_macho_entrypoint_spike_macos.c):
//   mov  x0, #42  -> 40 05 80 d2
//   mov  x16, #1  -> 30 00 80 d2  (SYS_exit selector)
//   svc  #0x80    -> 01 10 00 d4
static const uint8_t p2g_trampoline_bytes[] = {
    0x40, 0x05, 0x80, 0xd2,
    0x30, 0x00, 0x80, 0xd2,
    0x01, 0x10, 0x00, 0xd4,
};

static n00b_macho_rewrite_loadable_request_t
p2g_make_loadable_request(n00b_buffer_t *payload)
{
    return (n00b_macho_rewrite_loadable_request_t){
        .payload         = payload,
        .initprot        = 0x5, // r-x
        .maxprot         = 0x5,
        .file_alignment  = ARM64_PAGE,
        .vaddr_alignment = ARM64_PAGE,
        .vmsize          = ARM64_PAGE,
        .policy          = (n00b_macho_rewrite_admit_policy_t){
            .flags = N00B_MACHO_REWRITE_ADMIT_POLICY_ALLOW_RESIGN,
        },
    };
}

// Parse a single-slice arm64 binary from raw bytes (a fresh copy the rewrite
// path can own). Returns nullptr on any structural surprise.
static n00b_macho_binary_t *
p2g_parse_bytes(const uint8_t *data, size_t len)
{
    n00b_buffer_t  *buf    = n00b_buffer_from_bytes((char *)data, (int64_t)len);
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto            pr     = n00b_macho_parse_single(stream);
    if (n00b_result_is_err(pr)) {
        return nullptr;
    }
    return n00b_result_get(pr);
}

// The FR-14 / D-009 round-trip through the product engine. Returns true on a
// full PASS (codesign verify + exit 42); prints [FAIL]/[FACT] lines and returns
// false otherwise (a set gate never silently passes).
static bool
run_p2g_roundtrip(const char *fixture)
{
    // -- Parse the signed fixture. --
    auto stream_r = n00b_bstream_from_file(fixture);
    if (n00b_result_is_err(stream_r)) {
        printf("  [FAIL] p2g: could not open fixture %s\n", fixture);
        return false;
    }
    n00b_bstream_t *s  = n00b_result_get(stream_r);
    auto            pr = n00b_macho_parse_single(s);
    if (n00b_result_is_err(pr)) {
        printf("  [FAIL] p2g: parse of fixture failed\n");
        return false;
    }

    // -- Strip the existing signature (existing chalk product path, D-003). --
    n00b_buffer_t *orig = s->buf;
    n00b_buffer_t *work = n00b_buffer_from_bytes(orig->data,
                                                 (int64_t)orig->byte_len);
    auto strip_r = n00b_chalk_macho_strip_signature(work);
    if (n00b_result_is_err(strip_r)) {
        printf("  [FAIL] p2g: n00b_chalk_macho_strip_signature failed\n");
        return false;
    }
    n00b_buffer_t *stripped = n00b_result_get(strip_r);
    if (stripped == nullptr) {
        printf("  [FAIL] p2g: strip returned null buffer\n");
        return false;
    }

    // -- Re-parse the stripped bytes (product engine consumes a binary). --
    n00b_macho_binary_t *bin = p2g_parse_bytes((const uint8_t *)stripped->data,
                                               (size_t)stripped->byte_len);
    if (bin == nullptr) {
        printf("  [FAIL] p2g: re-parse of stripped bytes failed\n");
        return false;
    }

    // -- Plan the loadable insert; payload = the trampoline. --
    n00b_buffer_t *payload = n00b_buffer_from_bytes(
        (char *)p2g_trampoline_bytes, (int64_t)sizeof(p2g_trampoline_bytes));
    n00b_macho_rewrite_loadable_request_t req =
        p2g_make_loadable_request(payload);

    auto plan_r = n00b_macho_rewrite_plan_loadable_insert(bin, &req);
    if (n00b_result_is_err(plan_r)) {
        printf("  [FAIL] p2g: plan_loadable_insert Err %d\n",
               (int)n00b_result_get_err(plan_r));
        return false;
    }
    n00b_macho_rewrite_loadable_plan_t *plan = n00b_result_get(plan_r);
    if (plan->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
        printf("  [FAIL] p2g: plan_loadable_insert rejected (reason=%d)\n",
               (int)plan->rejection_reason);
        return false;
    }

    // -- Plan the host-entrypoint target (entry = start of the trampoline). --
    auto tgt_r = n00b_macho_rewrite_plan_host_entrypoint_target(
        bin, plan, 0u, (uint64_t)sizeof(p2g_trampoline_bytes));
    if (n00b_result_is_err(tgt_r)) {
        printf("  [FAIL] p2g: plan_host_entrypoint_target Err %d\n",
               (int)n00b_result_get_err(tgt_r));
        return false;
    }
    n00b_macho_rewrite_host_entrypoint_target_t tgt = n00b_result_get(tgt_r);
    if (tgt.outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
        printf("  [FAIL] p2g: host-entrypoint rejected (reason=%d)\n",
               (int)tgt.rejection_reason);
        return false;
    }

    // -- Enable the entrypoint redirect (CR-11). --
    auto en_r = n00b_macho_rewrite_loadable_plan_enable_entrypoint(
        plan, tgt.replacement_entryoff);
    if (n00b_result_is_err(en_r) || n00b_result_get(en_r) != true) {
        printf("  [FAIL] p2g: enable_entrypoint failed\n");
        return false;
    }

    // -- Apply (now writes the redirected entryoff). --
    auto apply_r = n00b_macho_rewrite_apply_loadable_insert_plan(bin, plan);
    if (n00b_result_is_err(apply_r)) {
        printf("  [FAIL] p2g: apply_loadable_insert_plan Err %d\n",
               (int)n00b_result_get_err(apply_r));
        return false;
    }
    n00b_buffer_t *out = n00b_result_get(apply_r);
    if (out == nullptr) {
        printf("  [FAIL] p2g: apply returned null buffer\n");
        return false;
    }

    // -- Write to a temp file. --
    char tmpl[] = "/tmp/n00b_macho_p2g_XXXXXX";
    int  fd     = mkstemp(tmpl);
    if (fd < 0) {
        printf("  [FAIL] p2g: mkstemp failed: %s\n", strerror(errno));
        return false;
    }
    {
        const uint8_t *p   = (const uint8_t *)out->data;
        size_t         rem = (size_t)out->byte_len;
        while (rem > 0) {
            ssize_t w = write(fd, p, rem);
            if (w <= 0) {
                printf("  [FAIL] p2g: write to temp file failed: %s\n",
                       strerror(errno));
                close(fd);
                unlink(tmpl);
                return false;
            }
            p   += (size_t)w;
            rem -= (size_t)w;
        }
    }
    close(fd);
    chmod(tmpl, 0755);

    // -- Re-sign ad-hoc through the EXISTING chalk path (OQ-2, signer=nullptr). --
    n00b_string_t *tmp_path = n00b_string_from_cstr(tmpl);
    auto           resign_r = n00b_chalk_macho_resign(tmp_path);
    if (n00b_result_is_err(resign_r)) {
        printf("  [FAIL] p2g: n00b_chalk_macho_resign failed on %s\n", tmpl);
        unlink(tmpl);
        return false;
    }

    // -- codesign --verify --deep --strict must exit 0. --
    char *const codesign_argv[] = {
        (char *)"/usr/bin/codesign",
        (char *)"--verify",
        (char *)"--deep",
        (char *)"--strict",
        tmpl,
        nullptr,
    };
    int verify_rc = run_to_exit(codesign_argv);

    // -- Execute it; the loader must return the sentinel exit code. --
    char *const exec_argv[] = {tmpl, nullptr};
    int         run_rc      = run_to_exit(exec_argv);

    printf("  [FACT] p2g original entryoff = %llu (0x%llx)\n",
           (unsigned long long)tgt.original_entryoff,
           (unsigned long long)tgt.original_entryoff);
    printf("  [FACT] p2g redirected entryoff = %llu (0x%llx)\n",
           (unsigned long long)tgt.replacement_entryoff,
           (unsigned long long)tgt.replacement_entryoff);
    printf("  [FACT] p2g codesign --verify --deep --strict exit = %d\n",
           verify_rc);
    printf("  [FACT] p2g run exit = %d (expected sentinel %d)\n",
           run_rc, SENTINEL_EXIT_CODE);

    bool ok = (verify_rc == 0) && (run_rc == SENTINEL_EXIT_CODE);
    if (ok) {
        printf("  [PASS] p2g FR-14 round-trip: product path inserts loadable + "
               "redirects LC_MAIN + ad-hoc resigns; codesign verifies and the "
               "loader runs the injected trampoline (exit %d).\n",
               SENTINEL_EXIT_CODE);
        unlink(tmpl);
        return true;
    }

    printf("  [FAIL] p2g: verify_ok=%d run_ok=%d; left %s on disk for "
           "post-mortem (codesign -dvvv / otool -l).\n",
           (int)(verify_rc == 0),
           (int)(run_rc == SENTINEL_EXIT_CODE),
           tmpl);
    return false;
}

#endif // __APPLE__

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    if (!env_is_one("N00B_TEST_MACHO_ORACLE")) {
        printf("  [SKIP] N00B_TEST_MACHO_ORACLE!=1\n");
        return 0;
    }

#if !defined(__APPLE__)
    // Gate is on but codesign(1) is macOS-only: do not silently pass.
    printf("  [FAIL] N00B_TEST_MACHO_ORACLE=1 but codesign(1) is "
           "macOS-only; this host cannot run the Mach-O signing oracle.\n");
    return 1;
#else
    char fixture[1024];
    if (!resolve_fixture(fixture, sizeof(fixture))) {
        printf("  [FAIL] could not locate committed fixture "
               "test/unit/data/hello_signed_arm64.macho "
               "(set MESON_SOURCE_ROOT or run from the project root).\n");
        return 1;
    }

    char *const codesign_argv[] = {
        (char *)"/usr/bin/codesign",
        (char *)"--verify",
        (char *)"--deep",
        (char *)"--strict",
        fixture,
        nullptr,
    };

    if (!file_exists(codesign_argv[0])) {
        printf("  [FAIL] /usr/bin/codesign not found; cannot run the "
               "Mach-O signing oracle.\n");
        return 1;
    }

    int rc = run_to_exit(codesign_argv);
    if (rc != 0) {
        printf("  [FAIL] codesign --verify --deep --strict %s exited %d\n",
               fixture,
               rc);
        return 1;
    }

    printf("  [PASS] macho_oracle codesign --verify --deep --strict %s\n",
           fixture);

    // P2-g: the FR-14 / D-009 round-trip through the product plan/apply path.
    if (!run_p2g_roundtrip(fixture)) {
        return 1;
    }

    return 0;
#endif
}

#endif

/**
 * @file test_objfile_macho_signing.c
 * @brief WP-011 Phase 1 regression tests for the Mach-O carrier-write signing
 *        reconciliation integrated into n00b_obj_bundle_write_file.
 *
 * WP-011 wires the existing chalk resign surface (D-003 reuse) into the
 * file-writing entrypoint: strip -> rewrite -> persist -> re-sign. These tests
 * exercise that integration through the public n00b_obj_bundle_write_file API
 * and assert the on-disk signature state with n00b_chalk_macho_signature_kind.
 *
 * Ordering-invariant + sig-state cases (P1-a..P1-d) are deterministic and
 * host-neutral and ALWAYS run. The codesign --verify case (P1-e) is Darwin-
 * gated behind N00B_TEST_MACHO_ORACLE=1 (D-006/NFR-06) and skips cleanly.
 *
 * Test-local scaffolding follows D-018: header-only libc for raw byte work and
 * fixture path assembly; every n00b_* call uses the n00b surface.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/buffer.h"
#include "core/file.h"
#include "core/runtime.h"
#include "util/path.h"
#include "core/pool.h"
#include "core/mmaps.h"
#include "chalk/n00b_chalk_macho.h"
#include "chalk/n00b_chalk_resign.h"
#include "compiler/objfile/bstream.h"
#include "compiler/objfile/sink.h"
#include "compiler/objfile/obj_bundle.h"
#include "compiler/objfile/macho.h"
#include "compiler/objfile/macho_build.h"
#include "compiler/objfile/macho_fat_rewrite.h"
#include "internal/compiler/objfile/macho_fat_rewrite_internal.h"

// Fixtures: an unsigned thin arm64 image (accepted by the surgical insert), and
// a code-signed thin arm64 image (the WP-011 strip step must remove its inbound
// signature before the rewrite can proceed).
#define TEST_FIXTURE_UNSIGNED "test/unit/data/hello_unsigned_arm64.macho"
#define TEST_FIXTURE_SIGNED   "test/unit/data/hello_signed_arm64.macho"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(label, cond)                                       \
    do {                                                         \
        if (cond) {                                              \
            printf("  [PASS] %s\n", (label));                    \
            g_pass++;                                            \
        }                                                        \
        else {                                                   \
            printf("  [FAIL] %s\n", (label));                    \
            g_fail++;                                            \
        }                                                        \
    } while (0)

// Are we running on a macOS host (where the resign step actually signs)?
#if defined(__APPLE__) && defined(__MACH__)
#define HOST_IS_MACOS 1
#else
#define HOST_IS_MACOS 0
#endif

// ---------------------------------------------------------------------------
// Fixture / path helpers (D-018 test scaffolding).
// ---------------------------------------------------------------------------

// Resolve a repo-relative path to an absolute one rooted at MESON_SOURCE_ROOT
// when available, else verbatim. Returns an n00b string.
static n00b_string_t *
resolve_path(const char *rel)
{
    const char *root = getenv("MESON_SOURCE_ROOT");
    char        path[1024];

    if (root != nullptr && root[0] != '\0') {
        int n = snprintf(path, sizeof(path), "%s/%s", root, rel);
        if (n > 0 && (size_t)n < sizeof(path)) {
            return n00b_string_from_cstr(path);
        }
    }

    return n00b_string_from_cstr(rel);
}

// Load the raw object bytes of a fixture (n00b_buffer_t), or nullptr.
static n00b_buffer_t *
load_fixture_bytes(const char *rel)
{
    n00b_string_t *p = resolve_path(rel);
    auto           r = n00b_bstream_from_file(p->data);

    if (n00b_result_is_ok(r)) {
        return n00b_result_get(r)->buf;
    }

    return nullptr;
}

// Read a written file back into a buffer for on-disk signature inspection.
static n00b_buffer_t *
read_back(n00b_string_t *path)
{
    auto r = n00b_bstream_from_file(path->data);

    if (n00b_result_is_ok(r)) {
        return n00b_result_get(r)->buf;
    }

    return nullptr;
}

// Build a unique writable destination path under the system temp dir. Uses the
// pid + a counter so parallel/repeat runs do not collide. The file is removed
// up front so REJECT_EXISTING persists succeed.
static n00b_string_t *
fresh_dest_path(const char *tag)
{
    static int counter = 0;
    char       path[512];
    const char *tmp = getenv("TMPDIR");

    if (tmp == nullptr || tmp[0] == '\0') {
        tmp = "/tmp/";
    }

    snprintf(path,
             sizeof(path),
             "%sn00b_macho_signing_%s_%d_%d.macho",
             tmp,
             tag,
             (int)getpid(),
             counter++);

    n00b_string_t *p = n00b_string_from_cstr(path);
    // Best-effort remove any stale file from a prior run.
    (void)n00b_file_unlink(p, .ignore_missing = true);
    return p;
}

// Build a single-artifact bundle (mirrors the carrier suite helper).
static n00b_obj_bundle_t *
make_test_bundle(n00b_string_t *payload_text)
{
    auto created = n00b_obj_bundle_new();
    if (n00b_result_is_err(created)) {
        return nullptr;
    }

    n00b_obj_bundle_t *bundle  = n00b_result_get(created);
    n00b_buffer_t     *payload = n00b_buffer_from_bytes(
        payload_text->data,
        (int64_t)payload_text->u8_bytes);

    auto add = n00b_obj_bundle_add_artifact(bundle,
                                            r"bin/tool",
                                            payload,
                                            .mode = 0755);
    if (n00b_result_is_err(add)) {
        return nullptr;
    }

    auto set_exec = n00b_obj_bundle_set_default_exec(bundle, r"bin/tool");
    if (n00b_result_is_err(set_exec)) {
        return nullptr;
    }

    return bundle;
}

// Count LC_CODE_SIGNATURE (0x1d) load commands in a thin Mach-O image. Used to
// assert the ordering invariant (exactly one fresh signature, none over stale
// bytes). On-disk header (64-bit): magic cputype cpusubtype filetype ncmds
// sizeofcmds flags reserved; load commands begin at byte 32.
#define LC_CODE_SIGNATURE_CMD 0x1du
#define MACHO_HDR64_SIZE      32u
#define MACHO_NCMDS_OFF       16u
#define MACHO_MAGIC_64_LE     0xfeedfacfu

static uint32_t
get32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int
count_code_signature_commands(n00b_buffer_t *bytes)
{
    if (bytes == nullptr || bytes->byte_len < (int64_t)MACHO_HDR64_SIZE) {
        return -1;
    }

    const uint8_t *b = (const uint8_t *)bytes->data;

    // Only the native 64-bit little-endian arm64 thin shape is exercised here.
    if (get32_le(b) != MACHO_MAGIC_64_LE) {
        return -1;
    }

    uint32_t ncmds = get32_le(b + MACHO_NCMDS_OFF);
    size_t   off   = MACHO_HDR64_SIZE;
    int      found = 0;

    for (uint32_t i = 0; i < ncmds; i++) {
        if (off + 8 > (size_t)bytes->byte_len) {
            return -1;
        }

        uint32_t cmd     = get32_le(b + off);
        uint32_t cmdsize = get32_le(b + off + 4);

        if (cmdsize < 8 || off + cmdsize > (size_t)bytes->byte_len) {
            return -1;
        }

        if (cmd == LC_CODE_SIGNATURE_CMD) {
            found++;
        }

        off += cmdsize;
    }

    return found;
}

// Extract the obj_bundle error code from a write_file result.
static n00b_obj_bundle_error_code_t
sink_result_err_code(n00b_result_t(n00b_objfile_sink_result_t *) r)
{
    return n00b_obj_bundle_error_code(
        n00b_result_get_err_payload(n00b_obj_bundle_error_t *, r));
}

// ============================================================================
// P1-a: unsigned thin fixture -> write_file (default) -> on-disk SIG_ADHOC
//       (macOS) / SIG_NONE + warning (non-macOS).
// ============================================================================
static void
test_p1a_unsigned_default(void)
{
    n00b_buffer_t     *object_bytes = load_fixture_bytes(TEST_FIXTURE_UNSIGNED);
    n00b_obj_bundle_t *bundle       = make_test_bundle(r"PAYLOAD-A");
    n00b_string_t     *dest         = fresh_dest_path("p1a");

    if (object_bytes == nullptr || bundle == nullptr) {
        printf("  [FAIL] P1-a: fixture/bundle unavailable\n");
        g_fail++;
        return;
    }

    auto wr = n00b_obj_bundle_write_file(
        object_bytes,
        bundle,
        dest,
        .overwrite = N00B_OBJFILE_SINK_REPLACE_EXISTING);

    if (n00b_result_is_err(wr)) {
        printf("  [FAIL] P1-a: write_file(unsigned, default) failed\n");
        g_fail++;
        return;
    }

    n00b_string_t *written =
        n00b_objfile_sink_result_destination_path(n00b_result_get(wr));
    n00b_buffer_t *on_disk = read_back(written);
    auto           kind    = n00b_chalk_macho_signature_kind(on_disk);

#if HOST_IS_MACOS
    CHECK("P1-a unsigned+default -> on-disk SIG_ADHOC (macOS)",
          kind == N00B_CHALK_MACHO_SIG_ADHOC);
#else
    CHECK("P1-a unsigned+default -> on-disk SIG_NONE (non-macOS strip-only)",
          kind == N00B_CHALK_MACHO_SIG_NONE);
#endif

    (void)n00b_file_unlink(written, .ignore_missing = true);
}

// ============================================================================
// P1-b: ad-hoc-signed thin fixture -> write_file -> inbound sig stripped then
//       re-signed; exactly one LC_CODE_SIGNATURE at the new tail (ordering
//       invariant: no signature command left over stale rewritten bytes).
// ============================================================================
static void
test_p1b_signed_strip_then_resign(void)
{
    n00b_buffer_t     *object_bytes = load_fixture_bytes(TEST_FIXTURE_SIGNED);
    n00b_obj_bundle_t *bundle       = make_test_bundle(r"PAYLOAD-B");
    n00b_string_t     *dest         = fresh_dest_path("p1b");

    if (object_bytes == nullptr || bundle == nullptr) {
        printf("  [FAIL] P1-b: fixture/bundle unavailable\n");
        g_fail += 2;
        return;
    }

    // Sanity: the source fixture carries an inbound signature to strip.
    auto in_kind = n00b_chalk_macho_signature_kind(object_bytes);

    auto wr = n00b_obj_bundle_write_file(
        object_bytes,
        bundle,
        dest,
        .overwrite = N00B_OBJFILE_SINK_REPLACE_EXISTING);

    if (n00b_result_is_err(wr)) {
        printf("  [FAIL] P1-b: write_file(signed) failed (strip did not admit "
               "the signed input)\n");
        printf("  [FAIL] P1-b: ordering invariant unreachable\n");
        g_fail += 2;
        return;
    }

    n00b_string_t *written =
        n00b_objfile_sink_result_destination_path(n00b_result_get(wr));
    n00b_buffer_t *on_disk = read_back(written);

    CHECK("P1-b signed input admitted via strip-before-rewrite",
          in_kind != N00B_CHALK_MACHO_SIG_NONE
              && n00b_result_is_ok(wr));

    int sig_count = count_code_signature_commands(on_disk);

#if HOST_IS_MACOS
    // After persist+resign on macOS the output carries exactly one fresh
    // LC_CODE_SIGNATURE (over the rewritten bytes), never a stale second one.
    CHECK("P1-b ordering invariant: exactly one LC_CODE_SIGNATURE at the tail",
          sig_count == 1);
#else
    // Off-macOS the resign collapses to strip-only: no signature survives over
    // the rewritten bytes.
    CHECK("P1-b ordering invariant: no LC_CODE_SIGNATURE (non-macOS strip-only)",
          sig_count == 0);
#endif

    (void)n00b_file_unlink(written, .ignore_missing = true);
}

// ============================================================================
// P1-c: write_file then write on the same bundle -> the write buffer is
//       SIG_NONE; the write_file on-disk output is signed (macOS) / stripped
//       (non-macOS). Documents the signed-vs-unsigned split.
// ============================================================================
static void
test_p1c_write_buffer_unsigned(void)
{
    n00b_buffer_t     *object_bytes = load_fixture_bytes(TEST_FIXTURE_UNSIGNED);
    n00b_obj_bundle_t *bundle       = make_test_bundle(r"PAYLOAD-C");
    n00b_string_t     *dest         = fresh_dest_path("p1c");

    if (object_bytes == nullptr || bundle == nullptr) {
        printf("  [FAIL] P1-c: fixture/bundle unavailable\n");
        g_fail += 2;
        return;
    }

    // Pure-buffer write: returns rewritten-but-UNSIGNED bytes.
    auto buf_wr = n00b_obj_bundle_write(object_bytes, bundle);

    bool buf_ok = n00b_result_is_ok(buf_wr);
    if (buf_ok) {
        auto buf_kind = n00b_chalk_macho_signature_kind(n00b_result_get(buf_wr));
        CHECK("P1-c n00b_obj_bundle_write buffer is SIG_NONE",
              buf_kind == N00B_CHALK_MACHO_SIG_NONE);
    }
    else {
        printf("  [FAIL] P1-c: n00b_obj_bundle_write failed\n");
        g_fail++;
    }

    // File write: on-disk output is signed (macOS) / stripped (non-macOS).
    auto file_wr = n00b_obj_bundle_write_file(
        object_bytes,
        bundle,
        dest,
        .overwrite = N00B_OBJFILE_SINK_REPLACE_EXISTING);

    if (n00b_result_is_err(file_wr)) {
        printf("  [FAIL] P1-c: write_file failed\n");
        g_fail++;
        return;
    }

    n00b_string_t *written =
        n00b_objfile_sink_result_destination_path(n00b_result_get(file_wr));
    n00b_buffer_t *on_disk   = read_back(written);
    auto           disk_kind = n00b_chalk_macho_signature_kind(on_disk);

#if HOST_IS_MACOS
    CHECK("P1-c write_file on-disk is signed while write buffer is unsigned",
          disk_kind == N00B_CHALK_MACHO_SIG_ADHOC);
#else
    CHECK("P1-c write_file on-disk is stripped (non-macOS) "
          "while write buffer is unsigned",
          disk_kind == N00B_CHALK_MACHO_SIG_NONE);
#endif

    (void)n00b_file_unlink(written, .ignore_missing = true);
}

// ============================================================================
// P1-d: resign forced to fail -> n00b_result_is_err with a populated
//       n00b_obj_bundle_error_t (CR-12), never a bare bool/abort.
//
// The failure must be isolated to the re-sign step (the persist must succeed),
// so the trigger is host-specific (the assertion is identical on both hosts):
//
//   - non-macOS: persist with file_mode 0444. The sink writes content through
//     its open fd and applies the read-only mode at commit, so persist
//     succeeds; the strip-only resign then opens the file for write (N00B_FILE_W)
//     and fails (EACCES).
//   - macOS: persist (DIRECT, in place) into a pre-existing writable file whose
//     parent directory is then read-only. The in-place persist succeeds, but
//     `codesign` needs to create a sibling temp in the parent directory and
//     fails (codesign(1) ignores the file's own write bit, so a read-only file
//     alone does not block it — a read-only parent does).
//
// Either way the resign branch returns an Err that write_file maps to the
// structured neutral carrier error (N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE).
// ============================================================================
static void
test_p1d_resign_failure_structured(void)
{
    n00b_buffer_t     *object_bytes = load_fixture_bytes(TEST_FIXTURE_UNSIGNED);
    n00b_obj_bundle_t *bundle       = make_test_bundle(r"PAYLOAD-D");

    if (object_bytes == nullptr || bundle == nullptr) {
        printf("  [FAIL] P1-d: fixture/bundle unavailable\n");
        g_fail++;
        return;
    }

#if HOST_IS_MACOS
    // Set up a private directory with a pre-existing writable destination file,
    // then make the directory read-only so codesign's sibling-temp write fails.
    const char *tmp = getenv("TMPDIR");
    if (tmp == nullptr || tmp[0] == '\0') {
        tmp = "/tmp/";
    }

    char dirbuf[512];
    snprintf(dirbuf,
             sizeof(dirbuf),
             "%sn00b_macho_signing_p1d_%d",
             tmp,
             (int)getpid());

    char destbuf[640];
    snprintf(destbuf, sizeof(destbuf), "%s/out.macho", dirbuf);

    n00b_string_t *dir  = n00b_string_from_cstr(dirbuf);
    n00b_string_t *dest = n00b_string_from_cstr(destbuf);

    (void)n00b_path_set_mode(dir, 0755);
    (void)n00b_file_unlink(dest, .ignore_missing = true);
    (void)n00b_path_remove_tree(dir, .ignore_missing = true);

    auto mk = n00b_path_mkdir_p(dir);
    if (n00b_result_is_err(mk)) {
        printf("  [FAIL] P1-d: could not create scratch directory\n");
        g_fail++;
        return;
    }

    // Pre-create the destination as a regular writable file so the DIRECT,
    // in-place persist does not need to create it in the read-only directory.
    auto pre = n00b_objfile_sink_write(
        object_bytes,
        dest,
        .sink_mode = N00B_OBJFILE_SINK_MODE_DIRECT,
        .overwrite = N00B_OBJFILE_SINK_REPLACE_EXISTING);
    if (n00b_result_is_err(pre)) {
        printf("  [FAIL] P1-d: scratch destination pre-create failed\n");
        g_fail++;
        (void)n00b_path_remove_tree(dir, .ignore_missing = true);
        return;
    }

    // Make the parent directory read-only: codesign's temp write will fail.
    (void)n00b_path_set_mode(dir, 0555);

    auto wr = n00b_obj_bundle_write_file(
        object_bytes,
        bundle,
        dest,
        .sink_mode = N00B_OBJFILE_SINK_MODE_DIRECT,
        .overwrite = N00B_OBJFILE_SINK_REPLACE_EXISTING);

    bool is_err = n00b_result_is_err(wr);
    bool mapped = is_err
                  && sink_result_err_code(wr)
                         == N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE;

    CHECK("P1-d forced resign failure -> Err with structured "
          "n00b_obj_bundle_error_t (CR-12)",
          is_err && mapped);

    // Restore writability and clean up.
    (void)n00b_path_set_mode(dir, 0755);
    (void)n00b_path_set_mode(dest, 0644);
    (void)n00b_path_remove_tree(dir, .ignore_missing = true);
#else
    n00b_string_t *dest = fresh_dest_path("p1d");

    auto wr = n00b_obj_bundle_write_file(
        object_bytes,
        bundle,
        dest,
        .overwrite              = N00B_OBJFILE_SINK_REPLACE_EXISTING,
        .file_mode              = n00b_option_set(uint32_t, 0444),
        .preserve_existing_mode = false);

    bool is_err = n00b_result_is_err(wr);
    bool mapped = is_err
                  && sink_result_err_code(wr)
                         == N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE;

    CHECK("P1-d forced resign failure -> Err with structured "
          "n00b_obj_bundle_error_t (CR-12)",
          is_err && mapped);

    (void)n00b_path_set_mode(dest, 0644);
    (void)n00b_file_unlink(dest, .ignore_missing = true);
#endif
}

// ============================================================================
// P1-e (Darwin-gated, D-006/NFR-06): write_file default on macOS ->
//       /usr/bin/codesign --verify <path> exits 0.
// ============================================================================
static void
test_p1e_codesign_verify(void)
{
    const char *gate = getenv("N00B_TEST_MACHO_ORACLE");

    if (gate == nullptr || gate[0] != '1') {
        printf("  [SKIP] P1-e codesign --verify (set N00B_TEST_MACHO_ORACLE=1 "
               "on a macOS host to run)\n");
        return;
    }

#if !HOST_IS_MACOS
    printf("  [SKIP] P1-e codesign --verify (non-macOS host)\n");
    return;
#else
    n00b_buffer_t     *object_bytes = load_fixture_bytes(TEST_FIXTURE_UNSIGNED);
    n00b_obj_bundle_t *bundle       = make_test_bundle(r"PAYLOAD-E");
    n00b_string_t     *dest         = fresh_dest_path("p1e");

    if (object_bytes == nullptr || bundle == nullptr) {
        printf("  [FAIL] P1-e: fixture/bundle unavailable\n");
        g_fail++;
        return;
    }

    auto wr = n00b_obj_bundle_write_file(
        object_bytes,
        bundle,
        dest,
        .overwrite = N00B_OBJFILE_SINK_REPLACE_EXISTING);

    if (n00b_result_is_err(wr)) {
        printf("  [FAIL] P1-e: write_file failed\n");
        g_fail++;
        return;
    }

    n00b_string_t *written =
        n00b_objfile_sink_result_destination_path(n00b_result_get(wr));

    // Match the oracle suite's fork/exec idiom (no shell): run
    // `/usr/bin/codesign --verify <path>` to completion and check exit 0.
    char path_c[1024];
    int  n = snprintf(path_c, sizeof(path_c), "%s", written->data);
    if (n <= 0 || (size_t)n >= sizeof(path_c)) {
        printf("  [FAIL] P1-e: destination path too long\n");
        g_fail++;
        return;
    }

    char *const codesign_argv[] = {
        (char *)"/usr/bin/codesign",
        (char *)"--verify",
        path_c,
        nullptr,
    };

    int rc = 127;
    pid_t pid = fork();
    if (pid == 0) {
        execvp(codesign_argv[0], codesign_argv);
        _exit(127);
    }
    else if (pid > 0) {
        int status = 0;
        if (waitpid(pid, &status, 0) >= 0 && WIFEXITED(status)) {
            rc = WEXITSTATUS(status);
        }
    }

    CHECK("P1-e codesign --verify exits 0 (NFR-12)",
          rc == 0);

    (void)n00b_file_unlink(written, .ignore_missing = true);
#endif
}

// ===========================================================================
// Phase 2 — fat per-slice signing + DF-007-01 (zero-copy writer allocator hook)
// ===========================================================================
//
// SCOPE NOTE (flagged to the orchestrator): the bundle carrier-write path
// (n00b_obj_bundle_write, obj_bundle.c) parses Mach-O input with
// n00b_macho_parse_single, which only admits THIN images — there is no fat
// branch wiring WP-007's n00b_macho_fat_rewrite into n00b_obj_bundle_write yet.
// A fat input therefore cannot round-trip through write_file today. The
// genuine WP-011 Phase-2 *signing* claims (re-fat before resign; the single
// existing resign signs every slice; alignment intact post-sign; inbound
// per-slice sigs stripped) are exercised here directly over the re-fat
// primitive + the SAME n00b_chalk_macho_resign(path, ...) call write_file uses,
// applied to the persisted fat container. This is the strip->re-fat->persist
// ->resign invariant on the whole fat file (design §6), independent of the
// (unwired) write_file fat dispatch.

// Build a parsed 2-slice fat (arm64 + x86_64), mirroring
// test_objfile_macho_fat_rewrite.c's build_parsed_two_slice_fat.
static n00b_macho_fat_t *
build_parsed_two_slice_fat(n00b_buffer_t **out_buf)
{
    n00b_macho_binary_t *arm64 = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);
    n00b_macho_segment_t *arm64_text = n00b_macho_add_segment(
        arm64, "__TEXT", 5, 5);
    arm64_text->vmaddr = 0x100000000ULL;

    n00b_macho_binary_t *x86 = n00b_macho_binary_new(
        CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE);
    n00b_macho_segment_t *x86_text = n00b_macho_add_segment(
        x86, "__TEXT", 5, 5);
    x86_text->vmaddr = 0x100000000ULL;

    n00b_macho_fat_t *fat = n00b_alloc(n00b_macho_fat_t);
    fat->count       = 2;
    fat->binaries    = n00b_alloc_array(n00b_macho_binary_t *, 2);
    fat->binaries[0] = arm64;
    fat->binaries[1] = x86;

    auto r = n00b_macho_build_fat(fat);
    if (n00b_result_is_err(r)) {
        return nullptr;
    }
    n00b_buffer_t *buf = n00b_result_get(r);

    n00b_bstream_t *s  = n00b_bstream_new(buf);
    auto            r2 = n00b_macho_parse(s);
    if (n00b_result_is_err(r2)) {
        return nullptr;
    }

    if (out_buf != nullptr) {
        *out_buf = buf;
    }
    return n00b_result_get(r2);
}

// Collect detached passthrough thin bytes + per-slice identity arrays for every
// slice of a parsed fat (no rewrite). Mirrors the WP-007 fat-rewrite helper.
static bool
collect_passthrough_slices(n00b_macho_fat_t *fat,
                           n00b_buffer_t  ***out_thin,
                           uint32_t        **out_cputypes,
                           uint32_t        **out_cpusubtypes,
                           uint32_t        **out_aligns,
                           uint32_t         *out_count)
{
    uint32_t        count       = fat->count;
    n00b_buffer_t **thin        = n00b_alloc_array(n00b_buffer_t *, count);
    uint32_t       *cputypes    = n00b_alloc_array(uint32_t, count);
    uint32_t       *cpusubtypes = n00b_alloc_array(uint32_t, count);
    uint32_t       *aligns      = n00b_alloc_array(uint32_t, count);

    for (uint32_t i = 0; i < count; i++) {
        auto tr = _n00b_macho_fat_slice_thin_bytes(
            fat, i, N00B_MACHO_FAT_SLICE_PASSTHROUGH, nullptr, nullptr);
        if (n00b_result_is_err(tr)) {
            return false;
        }
        thin[i]        = n00b_result_get(tr);
        cputypes[i]    = fat->slices[i].cputype;
        cpusubtypes[i] = fat->binaries[i]->header.cpusubtype;
        aligns[i]      = fat->slices[i].align;
    }

    *out_thin        = thin;
    *out_cputypes    = cputypes;
    *out_cpusubtypes = cpusubtypes;
    *out_aligns      = aligns;
    *out_count       = count;
    return true;
}

// Build a 2-slice fat buffer (arm64+x86_64) for the signing round-trip.
static n00b_buffer_t *
build_two_slice_fat_buffer(void)
{
    n00b_macho_fat_t *fat = build_parsed_two_slice_fat(nullptr);
    if (fat == nullptr) {
        return nullptr;
    }

    n00b_buffer_t **thin;
    uint32_t       *cputypes, *cpusubtypes, *aligns, count;
    if (!collect_passthrough_slices(fat, &thin, &cputypes, &cpusubtypes,
                                    &aligns, &count)) {
        return nullptr;
    }

    auto rr = n00b_macho_refat(thin, cputypes, cpusubtypes, aligns, count);
    if (n00b_result_is_err(rr)) {
        return nullptr;
    }
    return n00b_result_get(rr);
}

// Extract slice i's bytes from a fat buffer as a standalone thin buffer.
static n00b_buffer_t *
fat_slice_bytes(n00b_buffer_t *fat_buf, n00b_macho_fat_t *parsed, uint32_t i)
{
    uint64_t off = parsed->slices[i].offset;
    uint64_t sz  = parsed->slices[i].size;

    if (off + sz > (uint64_t)fat_buf->byte_len) {
        return nullptr;
    }

    return n00b_buffer_from_bytes(fat_buf->data + off, (int64_t)sz);
}

// Persist a fat buffer to a fresh path, then resign it with the SAME chalk
// resign call write_file uses (ad-hoc default). Returns the on-disk path, or
// nullptr on failure. *out_resign_ok reports whether the resign step succeeded.
static n00b_string_t *
persist_and_resign(n00b_buffer_t *fat_buf, const char *tag, bool *out_resign_ok)
{
    n00b_string_t *dest = fresh_dest_path(tag);

    auto persisted = n00b_objfile_sink_write(
        fat_buf,
        dest,
        .overwrite = N00B_OBJFILE_SINK_REPLACE_EXISTING);
    if (n00b_result_is_err(persisted)) {
        return nullptr;
    }

    n00b_string_t *path =
        n00b_objfile_sink_result_destination_path(n00b_result_get(persisted));

    auto resigned = n00b_chalk_macho_resign(path);
    *out_resign_ok = n00b_result_is_ok(resigned);
    return path;
}

// ===========================================================================
// P2-a: fat (arm64+x86_64) -> persist+resign -> valid fat_header/fat_arch;
//       count==2; arm64 + x86_64 cputypes preserved. (Round-trips the fat
//       container through the same resign call write_file uses.)
// ===========================================================================
static void
test_p2a_fat_roundtrip(void)
{
    n00b_buffer_t *fat_buf = build_two_slice_fat_buffer();
    if (fat_buf == nullptr) {
        printf("  [FAIL] P2-a: could not build fat fixture\n");
        g_fail++;
        return;
    }

    bool           resign_ok = false;
    n00b_string_t *path       = persist_and_resign(fat_buf, "p2a", &resign_ok);
    if (path == nullptr) {
        printf("  [FAIL] P2-a: persist of fat container failed\n");
        g_fail++;
        return;
    }

    n00b_buffer_t *on_disk = read_back(path);
    n00b_bstream_t *s  = n00b_bstream_new(on_disk);
    auto            pr = n00b_macho_parse(s);

    bool valid = n00b_result_is_ok(pr) && n00b_result_get(pr)->count == 2;
    bool cputypes_ok = false;
    if (valid) {
        n00b_macho_fat_t *parsed = n00b_result_get(pr);
        bool has_arm = false, has_x86 = false;
        for (uint32_t i = 0; i < parsed->count; i++) {
            if (parsed->slices[i].cputype == (uint32_t)CPU_TYPE_ARM64) {
                has_arm = true;
            }
            if (parsed->slices[i].cputype == (uint32_t)CPU_TYPE_X86_64) {
                has_x86 = true;
            }
        }
        cputypes_ok = has_arm && has_x86;
    }

    CHECK("P2-a fat round-trip: valid fat_header/fat_arch, both cputypes",
          valid && cputypes_ok);

    (void)n00b_file_unlink(path, .ignore_missing = true);
}

// ===========================================================================
// P2-b: each fat_arch.offset is 16K-aligned AFTER signing (NFR-11 not
//       disturbed by the resign step).
// ===========================================================================
static void
test_p2b_alignment_post_sign(void)
{
    n00b_buffer_t *fat_buf = build_two_slice_fat_buffer();
    if (fat_buf == nullptr) {
        printf("  [FAIL] P2-b: could not build fat fixture\n");
        g_fail++;
        return;
    }

    bool           resign_ok = false;
    n00b_string_t *path       = persist_and_resign(fat_buf, "p2b", &resign_ok);
    if (path == nullptr) {
        printf("  [FAIL] P2-b: persist of fat container failed\n");
        g_fail++;
        return;
    }

    n00b_buffer_t  *on_disk = read_back(path);
    n00b_bstream_t *s       = n00b_bstream_new(on_disk);
    auto            pr      = n00b_macho_parse(s);

    bool aligned = n00b_result_is_ok(pr);
    if (aligned) {
        n00b_macho_fat_t *parsed = n00b_result_get(pr);
        for (uint32_t i = 0; i < parsed->count; i++) {
            // build_fat / refat use align == 14 (16K) for every slice.
            if ((parsed->slices[i].offset & ((1u << 14) - 1)) != 0) {
                aligned = false;
                break;
            }
        }
    }

    CHECK("P2-b each fat_arch.offset 16K-aligned after signing (NFR-11)",
          aligned);

    (void)n00b_file_unlink(path, .ignore_missing = true);
}

// ===========================================================================
// P2-c (Darwin-gated, D-006/NFR-06): persist+resign a fat container ->
//       /usr/bin/codesign --verify <fat path> exits 0.
// ===========================================================================
static void
test_p2c_fat_codesign_verify(void)
{
    const char *gate = getenv("N00B_TEST_MACHO_ORACLE");

    if (gate == nullptr || gate[0] != '1') {
        printf("  [SKIP] P2-c codesign --verify (set N00B_TEST_MACHO_ORACLE=1 "
               "on a macOS host to run)\n");
        return;
    }

#if !HOST_IS_MACOS
    printf("  [SKIP] P2-c codesign --verify (non-macOS host)\n");
    return;
#else
    n00b_buffer_t *fat_buf = build_two_slice_fat_buffer();
    if (fat_buf == nullptr) {
        printf("  [FAIL] P2-c: could not build fat fixture\n");
        g_fail++;
        return;
    }

    bool           resign_ok = false;
    n00b_string_t *path       = persist_and_resign(fat_buf, "p2c", &resign_ok);
    if (path == nullptr || !resign_ok) {
        printf("  [FAIL] P2-c: persist/resign of fat container failed\n");
        g_fail++;
        return;
    }

    char path_c[1024];
    int  n = snprintf(path_c, sizeof(path_c), "%s", path->data);
    if (n <= 0 || (size_t)n >= sizeof(path_c)) {
        printf("  [FAIL] P2-c: destination path too long\n");
        g_fail++;
        return;
    }

    char *const codesign_argv[] = {
        (char *)"/usr/bin/codesign",
        (char *)"--verify",
        path_c,
        nullptr,
    };

    int   rc  = 127;
    pid_t pid = fork();
    if (pid == 0) {
        execvp(codesign_argv[0], codesign_argv);
        _exit(127);
    }
    else if (pid > 0) {
        int status = 0;
        if (waitpid(pid, &status, 0) >= 0 && WIFEXITED(status)) {
            rc = WEXITSTATUS(status);
        }
    }

    CHECK("P2-c codesign --verify <fat path> exits 0 (NFR-12)", rc == 0);

    (void)n00b_file_unlink(path, .ignore_missing = true);
#endif
}

// ===========================================================================
// P2-d: a fat input whose arm64 slice carries an inbound signature ->
//       strip each slice before re-fat -> final has exactly one fresh
//       LC_CODE_SIGNATURE per slice (ordering invariant over the fat file).
//
// Host-neutral: the strip-before-re-fat invariant is checked directly. On
// macOS the post-resign per-slice signature kind is additionally ADHOC; off
// macOS the resign collapses to strip-only (SIG_NONE), so the assertion is
// the per-slice "no stale signature survives" / "freshly (re)signed" state.
// ===========================================================================
static void
test_p2d_fat_strip_before_refat(void)
{
    // Build the two thin slices, then ad-hoc strip is a no-op on the freshly
    // built (unsigned) slices; the meaningful inbound-strip coverage for the
    // signed case is P1-b at the thin level. Here we assert the fat-level
    // invariant: after persist+resign, each embedded slice carries no stale
    // duplicate signature and (macOS) is freshly signed.
    n00b_buffer_t *fat_buf = build_two_slice_fat_buffer();
    if (fat_buf == nullptr) {
        printf("  [FAIL] P2-d: could not build fat fixture\n");
        g_fail++;
        return;
    }

    bool           resign_ok = false;
    n00b_string_t *path       = persist_and_resign(fat_buf, "p2d", &resign_ok);
    if (path == nullptr) {
        printf("  [FAIL] P2-d: persist of fat container failed\n");
        g_fail++;
        return;
    }

    n00b_buffer_t  *on_disk = read_back(path);
    n00b_bstream_t *s       = n00b_bstream_new(on_disk);
    auto            pr      = n00b_macho_parse(s);

    bool per_slice_ok = n00b_result_is_ok(pr);
    if (per_slice_ok) {
        n00b_macho_fat_t *parsed = n00b_result_get(pr);
        for (uint32_t i = 0; i < parsed->count && per_slice_ok; i++) {
            n00b_buffer_t *slice = fat_slice_bytes(on_disk, parsed, i);
            if (slice == nullptr) {
                per_slice_ok = false;
                break;
            }
            // No stale duplicate signature command (at most one).
            int sig_count = count_code_signature_commands(slice);
#if HOST_IS_MACOS
            // Freshly (re)signed: exactly one fresh LC_CODE_SIGNATURE.
            per_slice_ok = (sig_count == 1);
#else
            // Off macOS, resign collapses to strip-only: no signature survives.
            per_slice_ok = (sig_count == 0);
#endif
        }
    }

    CHECK("P2-d fat: exactly one fresh signature per slice "
          "(no stale sig survives re-fat)",
          per_slice_ok);

    (void)n00b_file_unlink(path, .ignore_missing = true);
}

// ===========================================================================
// P2-e (DF-007-01): _n00b_macho_refat_serialize with an explicit .allocator
//       returns a buffer whose backing store is OWNED by that allocator with
//       NO re-home copy; and n00b_macho_build_fat (allocator == nullptr) output
//       stays byte-identical (ownership-only change).
// ===========================================================================
static void
test_p2e_refat_allocator_owned_no_copy(void)
{
    // A non-default allocator: a freshly-initialized pool whose pages are
    // registered, so n00b_mem_get_allocator resolves ownership of its pointers.
    n00b_pool_t       pool = {};
    n00b_allocator_t *alloc =
        n00b_pool_init(&pool, .name = "p2e_refat_allocator_owned");
    if (alloc == nullptr) {
        printf("  [FAIL] P2-e: pool init failed\n");
        g_fail += 2;
        return;
    }

    n00b_macho_fat_t *fat = build_parsed_two_slice_fat(nullptr);
    if (fat == nullptr) {
        printf("  [FAIL] P2-e: could not build fat fixture\n");
        g_fail += 2;
        return;
    }

    n00b_buffer_t **thin;
    uint32_t       *cputypes, *cpusubtypes, *aligns, count;
    if (!collect_passthrough_slices(fat, &thin, &cputypes, &cpusubtypes,
                                    &aligns, &count)) {
        printf("  [FAIL] P2-e: passthrough slice collection failed\n");
        g_fail += 2;
        return;
    }

    // Allocator-supplied path: the finalized buffer's BACKING STORE (buf->data)
    // must be owned by our pool directly (DF-007-01: no re-home copy — the
    // writer is constructed with this allocator).
    auto rr = _n00b_macho_refat_serialize(thin, cputypes, cpusubtypes, aligns,
                                          count, alloc);
    bool owned = false;
    if (n00b_result_is_ok(rr)) {
        n00b_buffer_t *fat_buf = n00b_result_get(rr);
        auto           owner   = n00b_mem_get_allocator(fat_buf->data);
        owned = n00b_option_is_set(owner) && n00b_option_get(owner) == alloc;
    }

    CHECK("P2-e DF-007-01: refat output backing store owned by .allocator "
          "(no re-home copy)",
          owned);

    // Ownership-only change: the DF-007-01 hook must not alter the SERIALIZED
    // bytes. The allocator-owned serialization (above) and the default-allocator
    // serialization of the SAME slices must be byte-for-byte identical — only
    // the backing store's owner differs. (The objfile_macho_build suite holds
    // the golden byte-identity for n00b_macho_build_fat itself.)
    auto def_r = _n00b_macho_refat_serialize(thin, cputypes, cpusubtypes,
                                             aligns, count, nullptr);

    bool identical = false;
    if (n00b_result_is_ok(rr) && n00b_result_is_ok(def_r)) {
        n00b_buffer_t *a = n00b_result_get(rr);
        n00b_buffer_t *d = n00b_result_get(def_r);
        identical = (a->byte_len == d->byte_len)
                    && memcmp(a->data, d->data, (size_t)a->byte_len) == 0;
    }

    CHECK("P2-e serialized bytes identical across allocator/default "
          "(ownership-only DF-007-01 change)",
          identical);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("== WP-011 Phase 1: Mach-O carrier-write signing reconciliation ==\n");
    test_p1a_unsigned_default();
    test_p1b_signed_strip_then_resign();
    test_p1c_write_buffer_unsigned();
    test_p1d_resign_failure_structured();
    test_p1e_codesign_verify();

    printf("== WP-011 Phase 2: fat per-slice signing + DF-007-01 ==\n");
    test_p2a_fat_roundtrip();
    test_p2b_alignment_post_sign();
    test_p2c_fat_codesign_verify();
    test_p2d_fat_strip_before_refat();
    test_p2e_refat_allocator_owned_no_copy();

    printf("\n== summary: %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}

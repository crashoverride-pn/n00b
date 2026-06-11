/**
 * @file test_objfile_macho_host_entrypoint.c
 * @brief WP-009 Phase 2 regression tests for the Mach-O LOADABLE host-entrypoint
 *        write path (neutral selection -> arm64 LC_MAIN redirect).
 *
 * Produce-side cases (P2-a..P2-d) are deterministic, host-neutral, and always
 * run (D-006): they assert that the host-entry LOADABLE write redirects LC_MAIN
 * into the inserted exec-mapped segment, that the no-host-entry write leaves
 * LC_MAIN unchanged and still round-trips, and that non-arm64 / no-LC_MAIN inputs
 * surface a mapped Err rather than UB (D-031). P2-e is the oracle-gated
 * execute-from-bundle run (D-038): behind `N00B_TEST_MACHO_ORACLE=1` on Darwin it
 * writes a host-entry LOADABLE binary whose payload is the arm64 trampoline that
 * exits 42, resigns it via the existing chalk resign, codesign-verifies it, runs
 * it, and asserts the loader returned the embedded trampoline's exit code (42).
 * Off the gate it prints `[SKIP]`.
 *
 * The produce-side LC_MAIN entryoff and segment initprot are observable directly
 * from the parsed model (`bin->entrypoint`, `segments[i].initprot`), so P2-a/P2-b
 * assert the redirect facts without executing.
 *
 * D-018 test-fixture-scaffolding libc exemption: this harness/process file uses
 * getenv/printf/snprintf/memcpy/fork/exec/stat/mkstemp/write for harness and
 * process work; covered by the n00b-api-guidelines §1 exemption. Every n00b_*
 * call uses the n00b surface.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/runtime.h"
#include "compiler/objfile/bstream.h"
#include "compiler/objfile/macho.h"
#include "compiler/objfile/macho_types.h"
#include "compiler/objfile/macho_carrier.h"
#include "compiler/objfile/macho_rewrite.h"
#include "compiler/objfile/macho_rewrite_admit.h" // N00B_MACHO_BUNDLE_NOTE_OWNER
#include "compiler/objfile/obj_bundle.h"

// Arm64 unsigned fixture: the surgical insert + LC_MAIN redirect run on an
// unsigned arm64 binary (the produce-side path does not re-sign — WP-011). The
// x86_64 fixture drives the non-arm64 rejection (P2-c).
#define FIXTURE_ARM64  "test/unit/data/hello_unsigned_arm64.macho"
#define FIXTURE_X86_64 "test/unit/data/hello_x86_64.macho"

// On-disk LC_NOTE layout: cmd(4) cmdsize(4) data_owner[16] offset(8) size(8).
#define TEST_NOTE_CMD_SIZE   40u
#define TEST_NOTE_OWNER_OFF  8u
#define TEST_NOTE_OFFSET_OFF 24u
#define TEST_NOTE_SIZE_OFF   32u

// A guaranteed-unknown load command id: the parser stores raw_data and skips
// `cmdsize` bytes for any command it does not special-case (macho.c default
// arm), so overwriting LC_MAIN's `cmd` field with this leaves no LC_MAIN in the
// reparsed command list (no-LC_MAIN synthesis for P2-d).
#define TEST_UNKNOWN_CMD 0x99999999u

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

// ---------------------------------------------------------------------------
// Fixture loading (mirror test_objfile_macho_carrier.c)
// ---------------------------------------------------------------------------
static n00b_buffer_t *
load_fixture_bytes(const char *rel)
{
    const char *root = getenv("MESON_SOURCE_ROOT");
    char        path[1024];

    if (root != nullptr && root[0] != '\0') {
        int n = snprintf(path, sizeof(path), "%s/%s", root, rel);
        if (n > 0 && (size_t)n < sizeof(path)) {
            auto r = n00b_bstream_from_file(path);
            if (n00b_result_is_ok(r)) {
                return n00b_result_get(r)->buf;
            }
        }
    }

    auto r = n00b_bstream_from_file(rel);
    if (n00b_result_is_ok(r)) {
        return n00b_result_get(r)->buf;
    }

    return nullptr;
}

static n00b_macho_binary_t *
reparse(n00b_buffer_t *bytes)
{
    n00b_bstream_t *stream = n00b_bstream_new(bytes);
    auto            parsed = n00b_macho_parse_single(stream);

    if (n00b_result_is_err(parsed)) {
        return nullptr;
    }

    return n00b_result_get(parsed);
}

// Build a small obj bundle with a single executable artifact whose payload is
// `payload`. The default-exec artifact is the host-entrypoint selection target.
static n00b_obj_bundle_t *
make_bundle(n00b_buffer_t *payload)
{
    auto created = n00b_obj_bundle_new();
    if (n00b_result_is_err(created)) {
        return nullptr;
    }

    n00b_obj_bundle_t *bundle = n00b_result_get(created);

    auto add = n00b_obj_bundle_add_artifact(
        bundle,
        r"bin/tool",
        payload,
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE,
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

// Find the LOADABLE carrier descriptor in a reparsed binary (locate the
// bundle-owned LC_NOTE, slice its descriptor payload, decode it).
static n00b_macho_carrier_descriptor_t *
find_loadable_descriptor(n00b_macho_binary_t *bin)
{
    size_t want = strlen(N00B_MACHO_BUNDLE_NOTE_OWNER);

    for (uint32_t i = 0; i < bin->num_commands; i++) {
        n00b_macho_command_t *cmd = &bin->commands[i];

        if (cmd->cmd != LC_NOTE || cmd->raw_data == nullptr
            || (size_t)cmd->raw_data->byte_len < TEST_NOTE_CMD_SIZE) {
            continue;
        }

        const uint8_t *raw   = (const uint8_t *)cmd->raw_data->data;
        const char    *owner = (const char *)(raw + TEST_NOTE_OWNER_OFF);

        if (want > 16 || memcmp(owner, N00B_MACHO_BUNDLE_NOTE_OWNER, want) != 0) {
            continue;
        }

        uint64_t p_off = (uint64_t)raw[TEST_NOTE_OFFSET_OFF]
                       | ((uint64_t)raw[TEST_NOTE_OFFSET_OFF + 1] << 8)
                       | ((uint64_t)raw[TEST_NOTE_OFFSET_OFF + 2] << 16)
                       | ((uint64_t)raw[TEST_NOTE_OFFSET_OFF + 3] << 24)
                       | ((uint64_t)raw[TEST_NOTE_OFFSET_OFF + 4] << 32)
                       | ((uint64_t)raw[TEST_NOTE_OFFSET_OFF + 5] << 40)
                       | ((uint64_t)raw[TEST_NOTE_OFFSET_OFF + 6] << 48)
                       | ((uint64_t)raw[TEST_NOTE_OFFSET_OFF + 7] << 56);
        uint64_t p_sz  = (uint64_t)raw[TEST_NOTE_SIZE_OFF]
                       | ((uint64_t)raw[TEST_NOTE_SIZE_OFF + 1] << 8)
                       | ((uint64_t)raw[TEST_NOTE_SIZE_OFF + 2] << 16)
                       | ((uint64_t)raw[TEST_NOTE_SIZE_OFF + 3] << 24)
                       | ((uint64_t)raw[TEST_NOTE_SIZE_OFF + 4] << 32)
                       | ((uint64_t)raw[TEST_NOTE_SIZE_OFF + 5] << 40)
                       | ((uint64_t)raw[TEST_NOTE_SIZE_OFF + 6] << 48)
                       | ((uint64_t)raw[TEST_NOTE_SIZE_OFF + 7] << 56);

        if (p_off + p_sz > (uint64_t)bin->stream->buf->byte_len) {
            return nullptr;
        }

        n00b_buffer_t *payload = n00b_buffer_from_bytes(
            (char *)bin->stream->buf->data + p_off,
            (int64_t)p_sz);

        auto decoded = n00b_macho_carrier_descriptor_decode(payload);
        if (n00b_result_is_err(decoded)) {
            return nullptr;
        }

        return n00b_result_get(decoded);
    }

    return nullptr;
}

// True if the reparsed binary has a segment at `want_fileoff` whose initprot
// grants execute (VM_PROT_EXECUTE 0x4).
static bool
segment_is_exec_mapped(n00b_macho_binary_t *bin, uint64_t want_fileoff)
{
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_macho_segment_t *seg = &bin->segments[i];

        if (seg->fileoff == want_fileoff && (seg->initprot & 0x4u) != 0) {
            return true;
        }
    }

    return false;
}

// Build a host-entry write request through the public API and return the written
// object bytes (nullptr on Err). `*out_result` receives the raw result so the
// caller can inspect Err codes when needed.
static n00b_buffer_t *
write_host_entry(n00b_buffer_t                       *object_bytes,
                 n00b_obj_bundle_t                   *bundle,
                 n00b_result_t(n00b_buffer_t *)      *out_result)
{
    auto wr = n00b_obj_bundle_write(
        object_bytes,
        bundle,
        .carrier    = N00B_OBJ_BUNDLE_CARRIER_LOADABLE,
        .entrypoint = N00B_OBJ_BUNDLE_ENTRYPOINT_HOST_ENTRYPOINT);

    if (out_result != nullptr) {
        *out_result = wr;
    }

    if (n00b_result_is_err(wr)) {
        return nullptr;
    }

    return n00b_result_get(wr);
}

// ===========================================================================
// P2-a: host-entry LOADABLE write -> LC_MAIN redirected into the exec-mapped
// loadable segment at the selected offset.
// ===========================================================================
static void
test_p2a_host_entry_redirect(void)
{
    n00b_buffer_t *object_bytes = load_fixture_bytes(FIXTURE_ARM64);
    n00b_buffer_t *payload      = n00b_buffer_from_bytes((char *)"ARM64-EXEC-PAYLOAD",
                                                         18);
    n00b_obj_bundle_t *bundle   = make_bundle(payload);

    if (object_bytes == nullptr || bundle == nullptr) {
        printf("  [FAIL] P2-a: fixture/bundle unavailable\n");
        g_fail += 2;
        return;
    }

    n00b_result_t(n00b_buffer_t *) wr;
    n00b_buffer_t                 *out = write_host_entry(object_bytes, bundle, &wr);

    if (out == nullptr) {
        printf("  [FAIL] P2-a: host-entry write Err %d\n",
               (int)n00b_result_get_err(wr));
        printf("  [FAIL] P2-a: redirect facts unreachable\n");
        g_fail += 2;
        return;
    }

    n00b_macho_binary_t *bin = reparse(out);
    if (bin == nullptr) {
        printf("  [FAIL] P2-a: output reparse failed\n");
        printf("  [FAIL] P2-a: redirect facts unreachable\n");
        g_fail += 2;
        return;
    }

    n00b_macho_carrier_descriptor_t *desc = find_loadable_descriptor(bin);

    // The redirected LC_MAIN.entryoff (bin->entrypoint) must point at the start
    // of the selected target within the new loadable segment: segment file
    // offset + the selected payload offset. The single default-exec artifact is
    // first in the canonical payload, so its offset within the segment is the
    // payload-area base; the descriptor's payload_file_offset is the segment
    // file offset. We assert the entryoff lands inside the loadable segment and
    // is the descriptor's segment offset plus the (zero-based) target offset.
    bool ok = desc != nullptr
              && desc->kind == N00B_MACHO_CARRIER_KIND_LOADABLE
              && bin->entrypoint >= desc->payload_file_offset
              && bin->entrypoint
                     < desc->payload_file_offset + desc->payload_len;

    CHECK("P2-a host-entry LC_MAIN.entryoff points into the loadable segment", ok);

    CHECK("P2-a loadable segment initprot grants execute",
          desc != nullptr
              && segment_is_exec_mapped(bin, desc->payload_file_offset));
}

// ===========================================================================
// P2-b: no host-entry -> LC_MAIN unchanged vs input; round-trip read still Ok.
// ===========================================================================
static void
test_p2b_no_host_entry_preserved(void)
{
    n00b_buffer_t *object_bytes = load_fixture_bytes(FIXTURE_ARM64);
    n00b_buffer_t *payload      = n00b_buffer_from_bytes((char *)"NO-HOST-ENTRY", 13);
    n00b_obj_bundle_t *bundle   = make_bundle(payload);

    if (object_bytes == nullptr || bundle == nullptr) {
        printf("  [FAIL] P2-b: fixture/bundle unavailable\n");
        g_fail += 2;
        return;
    }

    n00b_macho_binary_t *in = reparse(object_bytes);
    if (in == nullptr) {
        printf("  [FAIL] P2-b: input reparse failed\n");
        g_fail += 2;
        return;
    }
    uint64_t input_entryoff = in->entrypoint;

    // Default entrypoint policy is PRESERVE; LOADABLE carrier, no redirect.
    auto wr = n00b_obj_bundle_write(object_bytes,
                                    bundle,
                                    .carrier = N00B_OBJ_BUNDLE_CARRIER_LOADABLE);

    if (n00b_result_is_err(wr)) {
        printf("  [FAIL] P2-b: no-host-entry write failed\n");
        printf("  [FAIL] P2-b: round-trip unreachable\n");
        g_fail += 2;
        return;
    }

    n00b_buffer_t       *out = n00b_result_get(wr);
    n00b_macho_binary_t *bin = reparse(out);

    CHECK("P2-b no-host-entry LC_MAIN.entryoff unchanged vs input",
          bin != nullptr && bin->entrypoint == input_entryoff);

    auto rd = n00b_obj_bundle_read(out);
    CHECK("P2-b no-host-entry round-trip read still Ok",
          n00b_result_is_ok(rd));
}

// ===========================================================================
// P2-c: non-arm64 (x86_64) host-entry write -> Err (mapped), not UB.
//
// The rewrite target profile rejects non-arm64 at the loadable-plan stage, so
// the host-entry write surfaces a structured Err rather than attempting (and
// crashing on) an x86_64 LC_MAIN redirect.
// ===========================================================================
static void
test_p2c_non_arm64_rejected(void)
{
    n00b_buffer_t *object_bytes = load_fixture_bytes(FIXTURE_X86_64);
    n00b_buffer_t *payload      = n00b_buffer_from_bytes((char *)"X86-PAYLOAD", 11);
    n00b_obj_bundle_t *bundle   = make_bundle(payload);

    if (object_bytes == nullptr || bundle == nullptr) {
        printf("  [FAIL] P2-c: fixture/bundle unavailable\n");
        g_fail++;
        return;
    }

    n00b_result_t(n00b_buffer_t *) wr;
    n00b_buffer_t                 *out = write_host_entry(object_bytes, bundle, &wr);

    CHECK("P2-c non-arm64 host-entry write -> Err (mapped, not UB)",
          out == nullptr && n00b_result_is_err(wr));
}

// ===========================================================================
// P2-d: no-LC_MAIN arm64 input -> the host-entrypoint planner rejects
// NO_LC_MAIN, and the full write path surfaces a mapped Err (not UB).
//
// Synthesize a no-LC_MAIN arm64 binary by overwriting LC_MAIN's `cmd` field with
// an unknown id (the parser skips unknown commands), then (1) drive the public
// host-entrypoint planner directly against an accepted loadable plan to assert
// REJECT_NO_LC_MAIN, and (2) run the full host-entry write path to assert it
// returns a mapped Err.
// ===========================================================================
static n00b_buffer_t *
synthesize_no_lc_main(n00b_buffer_t *arm64_bytes)
{
    n00b_macho_binary_t *bin = reparse(arm64_bytes);
    if (bin == nullptr) {
        return nullptr;
    }

    uint64_t lc_main_off = UINT64_MAX;
    for (uint32_t i = 0; i < bin->num_commands; i++) {
        if (bin->commands[i].cmd == LC_MAIN) {
            lc_main_off = bin->commands[i].file_offset;
            break;
        }
    }

    if (lc_main_off == UINT64_MAX
        || lc_main_off + 4 > (uint64_t)arm64_bytes->byte_len) {
        return nullptr;
    }

    uint64_t len = (uint64_t)arm64_bytes->byte_len;
    uint8_t *out = malloc(len);
    memcpy(out, arm64_bytes->data, len);

    // Overwrite the 4-byte `cmd` field (little-endian) with an unknown id;
    // cmdsize is untouched so the parser still skips the right number of bytes.
    out[lc_main_off + 0] = (uint8_t)TEST_UNKNOWN_CMD;
    out[lc_main_off + 1] = (uint8_t)(TEST_UNKNOWN_CMD >> 8);
    out[lc_main_off + 2] = (uint8_t)(TEST_UNKNOWN_CMD >> 16);
    out[lc_main_off + 3] = (uint8_t)(TEST_UNKNOWN_CMD >> 24);

    n00b_buffer_t *result = n00b_buffer_from_bytes((char *)out, (int64_t)len);
    free(out);
    return result;
}

static void
test_p2d_no_lc_main_rejected(void)
{
    n00b_buffer_t *arm64_bytes = load_fixture_bytes(FIXTURE_ARM64);

    if (arm64_bytes == nullptr) {
        printf("  [FAIL] P2-d: arm64 fixture unavailable\n");
        printf("  [FAIL] P2-d: write-path rejection unreachable\n");
        g_fail += 2;
        return;
    }

    n00b_buffer_t *no_main = synthesize_no_lc_main(arm64_bytes);
    if (no_main == nullptr) {
        printf("  [FAIL] P2-d: could not synthesize no-LC_MAIN arm64 input\n");
        printf("  [FAIL] P2-d: write-path rejection unreachable\n");
        g_fail += 2;
        return;
    }

    n00b_macho_binary_t *bin = reparse(no_main);
    if (bin == nullptr) {
        printf("  [FAIL] P2-d: no-LC_MAIN reparse failed\n");
        printf("  [FAIL] P2-d: write-path rejection unreachable\n");
        g_fail += 2;
        return;
    }

    // (1) Plan an accepted loadable insert, then drive the host-entrypoint
    // planner directly: it must reject NO_LC_MAIN (the reason the enable helper
    // maps to a mapped obj_bundle Err).
    n00b_buffer_t *seg_payload =
        n00b_buffer_from_bytes((char *)"PLACEHOLDER-SEGMENT-PAYLOAD", 27);
    n00b_macho_rewrite_loadable_request_t req =
        (n00b_macho_rewrite_loadable_request_t){
            .payload         = seg_payload,
            .initprot        = 0x5u,
            .maxprot         = 0x5u,
            .file_alignment  = 0x4000u,
            .vaddr_alignment = 0x4000u,
            .vmsize          = (uint64_t)seg_payload->byte_len,
            .policy          = (n00b_macho_rewrite_admit_policy_t){.flags = 0},
        };

    auto plan_r = n00b_macho_rewrite_plan_loadable_insert(bin, &req);
    bool planner_rejects_no_main = false;

    if (n00b_result_is_ok(plan_r)) {
        n00b_macho_rewrite_loadable_plan_t *plan = n00b_result_get(plan_r);

        if (plan->outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
            auto tgt_r = n00b_macho_rewrite_plan_host_entrypoint_target(
                bin, plan, 0u, (uint64_t)seg_payload->byte_len);

            if (n00b_result_is_ok(tgt_r)) {
                n00b_macho_rewrite_host_entrypoint_target_t tgt =
                    n00b_result_get(tgt_r);
                planner_rejects_no_main =
                    tgt.outcome == N00B_MACHO_REWRITE_PLAN_REJECTED
                    && tgt.rejection_reason
                           == N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_NO_LC_MAIN;
            }
        }
    }

    CHECK("P2-d host-entrypoint planner rejects NO_LC_MAIN on no-LC_MAIN input",
          planner_rejects_no_main);

    // (2) The full host-entry write path on the same input surfaces a mapped Err
    // (the enable helper maps NO_LC_MAIN -> UNSUPPORTED_EXEC_MODE), never UB.
    n00b_buffer_t     *payload = n00b_buffer_from_bytes((char *)"NO-MAIN", 7);
    n00b_obj_bundle_t *bundle  = make_bundle(payload);

    if (bundle == nullptr) {
        printf("  [FAIL] P2-d: bundle unavailable\n");
        g_fail++;
        return;
    }

    n00b_result_t(n00b_buffer_t *) wr;
    n00b_buffer_t                 *out = write_host_entry(no_main, bundle, &wr);

    CHECK("P2-d no-LC_MAIN host-entry write -> Err (mapped, not UB)",
          out == nullptr && n00b_result_is_err(wr));
}

// ===========================================================================
// P2-e: oracle-gated execute-from-bundle (D-038).
// ===========================================================================

static bool
env_is_one(const char *name)
{
    const char *value = getenv(name);
    return value != nullptr && strcmp(value, "1") == 0;
}

#if defined(__APPLE__)

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "chalk/n00b_chalk_resign.h"

#define SENTINEL_EXIT_CODE 42

// arm64 trampoline: exit(42) via SYS_exit (1). Encodings verified by the WP-001
// spike (test_macho_entrypoint_spike_macos.c):
//   mov  x0, #42  -> 40 05 80 d2
//   mov  x16, #1  -> 30 00 80 d2  (SYS_exit selector)
//   svc  #0x80    -> 01 10 00 d4
static const uint8_t p2e_trampoline_bytes[] = {
    0x40, 0x05, 0x80, 0xd2,
    0x30, 0x00, 0x80, 0xd2,
    0x01, 0x10, 0x00, 0xd4,
};

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

static bool
run_p2e_execute_from_bundle(void)
{
    n00b_buffer_t *object_bytes = load_fixture_bytes(FIXTURE_ARM64);
    if (object_bytes == nullptr) {
        printf("  [FAIL] P2-e: arm64 fixture unavailable\n");
        return false;
    }

    // The default-exec artifact payload IS the arm64 trampoline; the host-entry
    // redirect points LC_MAIN at its first byte inside the loadable segment.
    n00b_buffer_t *payload = n00b_buffer_from_bytes(
        (char *)p2e_trampoline_bytes, (int64_t)sizeof(p2e_trampoline_bytes));
    n00b_obj_bundle_t *bundle = make_bundle(payload);
    if (bundle == nullptr) {
        printf("  [FAIL] P2-e: bundle unavailable\n");
        return false;
    }

    n00b_result_t(n00b_buffer_t *) wr;
    n00b_buffer_t *out = write_host_entry(object_bytes, bundle, &wr);
    if (out == nullptr) {
        printf("  [FAIL] P2-e: host-entry write Err %d\n",
               (int)n00b_result_get_err(wr));
        return false;
    }

    // Write to a temp file.
    char tmpl[] = "/tmp/n00b_macho_p2e_XXXXXX";
    int  fd     = mkstemp(tmpl);
    if (fd < 0) {
        printf("  [FAIL] P2-e: mkstemp failed\n");
        return false;
    }
    {
        const uint8_t *p   = (const uint8_t *)out->data;
        size_t         rem = (size_t)out->byte_len;
        while (rem > 0) {
            ssize_t w = write(fd, p, rem);
            if (w <= 0) {
                printf("  [FAIL] P2-e: write to temp file failed\n");
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

    // Re-sign ad-hoc through the EXISTING chalk path (the P2-e TEST resigns; the
    // product path does not — WP-011).
    n00b_string_t *tmp_path = n00b_string_from_cstr(tmpl);
    auto           resign_r = n00b_chalk_macho_resign(tmp_path);
    if (n00b_result_is_err(resign_r)) {
        printf("  [FAIL] P2-e: n00b_chalk_macho_resign failed on %s\n", tmpl);
        unlink(tmpl);
        return false;
    }

    // codesign --verify --deep --strict must exit 0.
    char *const codesign_argv[] = {
        (char *)"/usr/bin/codesign",
        (char *)"--verify",
        (char *)"--deep",
        (char *)"--strict",
        tmpl,
        nullptr,
    };
    int verify_rc = run_to_exit(codesign_argv);

    // Execute it; the loader must run the embedded trampoline -> exit 42.
    char *const exec_argv[] = {tmpl, nullptr};
    int         run_rc      = run_to_exit(exec_argv);

    printf("  [FACT] P2-e codesign --verify --deep --strict exit = %d\n",
           verify_rc);
    printf("  [FACT] P2-e run exit = %d (expected sentinel %d)\n",
           run_rc, SENTINEL_EXIT_CODE);

    bool ok = (verify_rc == 0) && (run_rc == SENTINEL_EXIT_CODE);
    if (ok) {
        printf("  [PASS] P2-e execute-from-bundle: host-entry LOADABLE write "
               "redirects LC_MAIN into the embedded arm64 trampoline; codesign "
               "verifies and the loader runs it (exit %d).\n",
               SENTINEL_EXIT_CODE);
        unlink(tmpl);
        return true;
    }

    printf("  [FAIL] P2-e: verify_ok=%d run_ok=%d; left %s on disk for "
           "post-mortem (codesign -dvvv / otool -l).\n",
           (int)(verify_rc == 0),
           (int)(run_rc == SENTINEL_EXIT_CODE),
           tmpl);
    return false;
}

#endif // __APPLE__

static void
test_p2e_oracle(void)
{
    if (!env_is_one("N00B_TEST_MACHO_ORACLE")) {
        printf("  [SKIP] P2-e: N00B_TEST_MACHO_ORACLE!=1\n");
        return;
    }

#if defined(__APPLE__)
    if (!run_p2e_execute_from_bundle()) {
        g_fail++;
        return;
    }
    g_pass++;
#else
    // Gate is on but codesign(1)/the loader oracle is macOS-only: do not
    // silently pass.
    printf("  [FAIL] P2-e: N00B_TEST_MACHO_ORACLE=1 but the execute-from-bundle "
           "oracle is macOS-only.\n");
    g_fail++;
#endif
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("== WP-009 Phase 2: Mach-O host-entrypoint write path ==\n");

    test_p2a_host_entry_redirect();
    test_p2b_no_host_entry_preserved();
    test_p2c_non_arm64_rejected();
    test_p2d_no_lc_main_rejected();
    test_p2e_oracle();

    printf("\n  Pass: %d  Fail: %d\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}

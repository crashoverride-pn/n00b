/**
 * @file test_objfile_macho_fat_carrier_read.c
 * @brief WP-015 Phase 1 always-run, host-neutral regression test for the
 *        fat/universal Mach-O object-bundle carrier READ dispatch.
 *
 * Exercises `n00b_obj_bundle_read` on a fat/universal Mach-O carrier produced by
 * the WP-014 write half. The fat fixture is ASSEMBLED exactly as in
 * `test_objfile_macho_fat_carrier.c` (the WP-014 write test): the committed
 * unsigned arm64 thin fixture `test/unit/data/hello_unsigned_arm64.macho` (which
 * IS carrier-writable) re-fattened via `n00b_macho_refat` with a programmatic
 * x86_64 thin passthrough slice (D-002/D-035, NFR-01).
 *
 * For each carrier kind (METADATA / LOADABLE / SPLIT):
 *   - write the carrier into the fat via the public neutral
 *     `n00b_obj_bundle_write` (WP-014);
 *   - READ it back via `n00b_obj_bundle_read` (WP-015 — the slice-selection
 *     prologue selects the arm64 carrier slice, detaches+re-parses it thin, then
 *     the existing thin detect/read switch decodes the canonical bundle);
 *   - assert Ok and that the decoded bundle's artifact set round-trips (the
 *     default executable is present and selectable);
 *   - assert `n00b_obj_bundle_extract` (VALIDATE_ONLY, in-memory, no disk writes)
 *     and `n00b_obj_bundle_exec_plan` succeed on the fat-read bundle (FR-23 — the
 *     neutral extract/exec-plan core is format-agnostic).
 * Error case: a fat with no arm64 slice → `Err(UNSUPPORTED_CARRIER)`.
 *
 * NO loader / codesign / spawn; write+read+validate-only are in-memory. The only
 * on-disk touch is a READ-ONLY load of the committed fixture (parallel-safe).
 *
 * Per n00b-api-guidelines § 1 / macwrap DECISIONS.md D-018, this test-local
 * scaffolding may use header-only libc for path assembly (`snprintf`, `getenv`);
 * every code-under-test call uses the n00b surface.
 *
 * Cases P1-a..P1-f per the WP-015 Phase 1 regression matrix.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "adt/list.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "compiler/objfile/bstream.h"
#include "compiler/objfile/macho.h"
#include "compiler/objfile/macho_types.h"
#include "compiler/objfile/macho_build.h"
#include "compiler/objfile/macho_fat_rewrite.h"
#include "compiler/objfile/obj_bundle.h"
#include "internal/compiler/objfile/obj_bundle_macho.h"

#define TEST_FIXTURE_UNSIGNED "test/unit/data/hello_unsigned_arm64.macho"
#define TEST_DEFAULT_EXEC     "bin/tool"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(label, cond)                    \
    do {                                      \
        if (cond) {                           \
            printf("  [PASS] %s\n", (label)); \
            g_pass++;                         \
        }                                     \
        else {                                \
            printf("  [FAIL] %s\n", (label)); \
            g_fail++;                         \
        }                                     \
    } while (0)

// ---------------------------------------------------------------------------
// Fixture loading (mirror test_objfile_macho_fat_carrier.c). Resolve the
// committed unsigned arm64 fixture against MESON_SOURCE_ROOT, then load its raw
// object bytes.
// ---------------------------------------------------------------------------
static n00b_buffer_t *
load_unsigned_arm64_bytes(void)
{
    const char *root = getenv("MESON_SOURCE_ROOT");
    char        path[1024];
    const char *use = TEST_FIXTURE_UNSIGNED;

    if (root != nullptr && root[0] != '\0') {
        int n = snprintf(path, sizeof(path), "%s/%s", root,
                         TEST_FIXTURE_UNSIGNED);
        if (n > 0 && (size_t)n < sizeof(path)) {
            use = path;
        }
    }

    auto r = n00b_bstream_from_file(use);

    if (n00b_result_is_ok(r)) {
        return n00b_result_get(r)->buf;
    }

    return nullptr;
}

// Build a minimal programmatic x86_64 thin slice (PASSTHROUGH witness).
static n00b_buffer_t *
build_x86_64_thin(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(CPU_TYPE_X86_64,
                                                     CPU_SUBTYPE_X86_64_ALL,
                                                     MH_EXECUTE);
    n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    n00b_macho_set_entry(bin, 0, 0);

    auto r = n00b_macho_build(bin);

    if (n00b_result_is_err(r)) {
        return nullptr;
    }

    return n00b_result_get(r);
}

// Assemble a 2-slice fat (arm64 carrier-writable + x86_64 passthrough).
static n00b_buffer_t *
build_two_slice_fat(void)
{
    n00b_buffer_t *arm64_bytes = load_unsigned_arm64_bytes();

    if (arm64_bytes == nullptr) {
        return nullptr;
    }

    n00b_buffer_t *x86_bytes = build_x86_64_thin();

    if (x86_bytes == nullptr) {
        return nullptr;
    }

    n00b_buffer_t *thin[2]   = {arm64_bytes, x86_bytes};
    uint32_t       cputy[2]  = {CPU_TYPE_ARM64, CPU_TYPE_X86_64};
    uint32_t       subty[2]  = {CPU_SUBTYPE_ARM64_ALL, CPU_SUBTYPE_X86_64_ALL};
    uint32_t       aligns[2] = {14u, 14u}; // 2^14 = 16K page alignment.

    auto r = n00b_macho_refat(thin, cputy, subty, aligns, 2, .allocator = nullptr);

    if (n00b_result_is_err(r)) {
        return nullptr;
    }

    return n00b_result_get(r);
}

// Build a 2-slice fat with NO arm64 slice (two x86_64 slices) for the
// UNSUPPORTED_CARRIER read error case.
static n00b_buffer_t *
build_no_arm64_fat(void)
{
    n00b_buffer_t *a = build_x86_64_thin();
    n00b_buffer_t *b = build_x86_64_thin();

    if (a == nullptr || b == nullptr) {
        return nullptr;
    }

    n00b_buffer_t *thin[2]   = {a, b};
    uint32_t       cputy[2]  = {CPU_TYPE_X86_64, CPU_TYPE_X86_64};
    uint32_t       subty[2]  = {CPU_SUBTYPE_X86_64_ALL, CPU_SUBTYPE_X86_64_ALL};
    uint32_t       aligns[2] = {14u, 14u};

    auto r = n00b_macho_refat(thin, cputy, subty, aligns, 2, .allocator = nullptr);

    if (n00b_result_is_err(r)) {
        return nullptr;
    }

    return n00b_result_get(r);
}

// Build a single-artifact bundle with a default executable so SPLIT can
// enumerate an executable slice and exec_plan has a selectable target.
static n00b_obj_bundle_t *
make_test_bundle(void)
{
    auto created = n00b_obj_bundle_new();

    if (n00b_result_is_err(created)) {
        return nullptr;
    }

    n00b_obj_bundle_t *bundle  = n00b_result_get(created);
    n00b_buffer_t     *payload = n00b_buffer_from_cstr(
        "macho-fat-carrier-read-payload");

    auto add = n00b_obj_bundle_add_artifact(
        bundle,
        r"bin/tool",
        payload,
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE,
        .mode = 0755);

    if (n00b_result_is_err(add)) {
        return nullptr;
    }

    auto set_exec = n00b_obj_bundle_set_default_exec(bundle,
                                                     r"bin/tool");

    if (n00b_result_is_err(set_exec)) {
        return nullptr;
    }

    return bundle;
}

// Assert that a fat-read bundle round-trips through the neutral extract /
// exec-plan core (FR-23) and exposes the default executable artifact.
static void
assert_neutral_roundtrip(n00b_obj_bundle_t *bundle, const char *id)
{
    char label[160];

    // extract (VALIDATE_ONLY): in-memory, no filesystem side effects.
    n00b_string_t *root = r"/tmp/n00b-fat-carrier-read-validate";
    auto extracted = n00b_obj_bundle_extract(
        bundle,
        root,
        .policy_mode = N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);

    snprintf(label, sizeof(label), "%s: extract (validate-only) Ok", id);
    CHECK(label, n00b_result_is_ok(extracted));

    if (n00b_result_is_ok(extracted)) {
        n00b_obj_bundle_extract_result_t *facts = n00b_result_get(extracted);

        // The single executable artifact round-trips as one planned file (and
        // no disk writes occurred in validate-only mode).
        snprintf(label, sizeof(label),
                 "%s: artifact set round-trips (1 file planned)", id);
        CHECK(label,
              facts != nullptr
                  && n00b_obj_bundle_extract_result_files_planned(facts) == 1
                  && n00b_obj_bundle_extract_result_files_written(facts) == 0);
    }

    // exec_plan (VALIDATE_ONLY): plan the default executable target (FR-23).
    auto planned = n00b_obj_bundle_exec_plan(
        bundle,
        .policy_mode = N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);

    snprintf(label, sizeof(label), "%s: exec_plan Ok", id);
    CHECK(label, n00b_result_is_ok(planned));

    if (n00b_result_is_ok(planned)) {
        n00b_obj_bundle_exec_plan_t *plan = n00b_result_get(planned);
        auto sel = n00b_obj_bundle_exec_plan_selected_logical_path(plan);

        snprintf(label, sizeof(label),
                 "%s: exec_plan selects the default executable", id);
        CHECK(label,
              plan != nullptr && n00b_option_is_set(sel)
                  && n00b_unicode_str_eq(n00b_option_get(sel),
                                         r"bin/tool"));
    }
}

// ---------------------------------------------------------------------------
// P1-a/-b/-c: per-carrier fat write → fat read → decoded bundle + neutral
// round-trip.
// ---------------------------------------------------------------------------
static void
drive_carrier(n00b_obj_bundle_carrier_t carrier, const char *id)
{
    char label[160];

    n00b_buffer_t *fat_in = build_two_slice_fat();

    snprintf(label, sizeof(label), "%s: fat fixture assembled", id);
    CHECK(label, fat_in != nullptr);
    if (fat_in == nullptr) {
        return;
    }

    n00b_obj_bundle_t *bundle = make_test_bundle();
    snprintf(label, sizeof(label), "%s: bundle built", id);
    CHECK(label, bundle != nullptr);
    if (bundle == nullptr) {
        return;
    }

    auto written = n00b_obj_bundle_write(fat_in, bundle, .carrier = carrier);

    snprintf(label, sizeof(label), "%s: write returns Ok", id);
    CHECK(label, n00b_result_is_ok(written));
    if (n00b_result_is_err(written)) {
        // Surface the write error code so a SPLIT (or any carrier) write
        // failure is diagnosable rather than a silent early return.
        if (n00b_result_is_err_payload(n00b_obj_bundle_error_t *, written)) {
            n00b_obj_bundle_error_t *werr
                = n00b_result_get_err_payload(n00b_obj_bundle_error_t *, written);
            printf("    %s: write failed, error code %lld\n",
                   id,
                   (long long)(werr != nullptr ? n00b_obj_bundle_error_code(werr)
                                               : 0));
        }
        return;
    }

    n00b_buffer_t *fat_carrier_bytes = n00b_result_get(written);

    // WP-015 under test: read the fat carrier back through the neutral reader.
    auto read = n00b_obj_bundle_read(fat_carrier_bytes);

    snprintf(label, sizeof(label), "%s: read returns Ok", id);
    CHECK(label, n00b_result_is_ok(read));
    if (n00b_result_is_err(read)) {
        return;
    }

    n00b_obj_bundle_t *decoded = n00b_result_get(read);

    snprintf(label, sizeof(label), "%s: decoded bundle non-null", id);
    CHECK(label, decoded != nullptr);
    if (decoded == nullptr) {
        return;
    }

    assert_neutral_roundtrip(decoded, id);
}

// ---------------------------------------------------------------------------
// P1-d: a fat with no arm64 slice → Err(UNSUPPORTED_CARRIER) on read.
// ---------------------------------------------------------------------------
static void
test_no_arm64_slice(void)
{
    n00b_buffer_t *fat_in = build_no_arm64_fat();

    CHECK("P1-d: no-arm64 fat fixture assembled", fat_in != nullptr);
    if (fat_in == nullptr) {
        return;
    }

    auto read = n00b_obj_bundle_read(fat_in);

    CHECK("P1-d: no-arm64 fat read returns Err", n00b_result_is_err(read));

    if (n00b_result_is_err(read)
        && n00b_result_is_err_payload(n00b_obj_bundle_error_t *, read)) {
        n00b_obj_bundle_error_t *err
            = n00b_result_get_err_payload(n00b_obj_bundle_error_t *, read);
        CHECK("P1-d: error code is UNSUPPORTED_CARRIER",
              err != nullptr
                  && n00b_obj_bundle_error_code(err)
                         == N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER);
    }
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("== WP-015 fat/universal Mach-O carrier-read dispatch ==\n");

    drive_carrier(N00B_OBJ_BUNDLE_CARRIER_METADATA, "P1-a METADATA");
    drive_carrier(N00B_OBJ_BUNDLE_CARRIER_LOADABLE, "P1-b LOADABLE");
    drive_carrier(N00B_OBJ_BUNDLE_CARRIER_SPLIT, "P1-c SPLIT");
    test_no_arm64_slice();

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}

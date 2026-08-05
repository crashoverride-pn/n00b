/**
 * @file test_objfile_macho_e2e.c
 * @brief WP-012 Phase 1 always-run, host-neutral structural end-to-end test
 *        for the Mach-O object-bundle pipeline (FR-23 / NFR-10 evidence).
 *
 * For each carrier kind (METADATA / LOADABLE / SPLIT) this test builds a
 * bundle, embeds a payload artifact, writes a real Mach-O carrier into a
 * parseable unsigned arm64 object via the public neutral
 * `n00b_obj_bundle_write`, then reads the carrier back through the neutral
 * `n00b_obj_bundle_read` and drives the FORMAT-NEUTRAL core verbatim:
 *   - `n00b_obj_bundle_extract` (validate-only AND default atomic), and
 *   - `n00b_obj_bundle_exec_plan`,
 * asserting only the neutral exec-plan / extract-result accessors. No loader,
 * no codesign, no posix_spawn/fork/exec: this is a structural e2e that is
 * deterministic and passes on Linux as well as un-gated macOS (D-006 / NFR-06).
 *
 * Because the extract/exec-plan core is reached only through the neutral
 * `n00b_obj_bundle_*` surface (never a Mach-O-specific extract/exec symbol),
 * this test is the executable evidence for FR-23 (format-neutral
 * extraction/execution reuse) and NFR-10 (neutral-core immutability).
 *
 * The carrier-write TARGET is the committed unsigned arm64 fixture
 * `test/unit/data/hello_unsigned_arm64.macho`, resolved via
 * `MESON_SOURCE_ROOT` — the exact mechanism the existing public-write
 * Mach-O carrier tests use (`test_objfile_macho_carrier.c`,
 * `test_objfile_macho_signing.c`): the WP-008/009/010 carrier-write path
 * rejects code-signed inputs (no resign in the buffer path), so a clean
 * unsigned arm64 base is required. The casegen builder output is not used as a
 * public-write target by any landed test; the fixture is the verified target.
 *
 * COVERAGE MAP: the GATED Mach-O proofs (FR-14 round-trip + execute exit 42,
 * FR-25 execute-from-bundle, NFR-12 codesign --verify, NFR-06 host gating)
 * are already landed and are NOT recreated here. See the standalone artifact
 * `.agents/work-plans/wp-012-e2e-execution-and-oracle/coverage-map.md` for the
 * requirement-to-test mapping.
 *
 * Per n00b-api-guidelines § 1 / macwrap DECISIONS.md D-018, this test-local
 * scaffolding may use header-only libc for path assembly (`snprintf`,
 * `getenv`); every code-under-test call uses the n00b surface.
 *
 * Cases P1-a..P1-e per the Phase 1 regression matrix.
 */
#include <stdio.h>
#include <stdlib.h>

#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "util/assert.h"
#include "util/path.h"
#include "compiler/objfile/bstream.h"
#include "compiler/objfile/obj_bundle.h"

#define N00B_TEST_REQUIRE(expr) n00b_require((expr), #expr)

#define TEST_FIXTURE_UNSIGNED "test/unit/data/hello_unsigned_arm64.macho"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(label, cond)                   \
    do {                                     \
        if (cond) {                          \
            printf("  [PASS] %s\n", (label)); \
            g_pass++;                        \
        }                                    \
        else {                               \
            printf("  [FAIL] %s\n", (label)); \
            g_fail++;                        \
        }                                    \
    } while (0)

// ---------------------------------------------------------------------------
// Fixture loading (mirror test_objfile_macho_signing.c:load_fixture_bytes).
// Resolve a repo-relative path against MESON_SOURCE_ROOT when set, else use it
// verbatim, then load the raw object bytes.
// ---------------------------------------------------------------------------
static n00b_buffer_t *
load_target_bytes(void)
{
    const char *root = getenv("MESON_SOURCE_ROOT");
    char        path[1024];
    const char *use = TEST_FIXTURE_UNSIGNED;

    if (root != nullptr && root[0] != '\0') {
        int n = snprintf(path, sizeof(path), "%s/%s", root, TEST_FIXTURE_UNSIGNED);
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

// Build a single-artifact bundle with a default executable so exec-plan
// selection resolves deterministically (mirrors the carrier-suite helper).
static n00b_obj_bundle_t *
make_test_bundle(void)
{
    auto created = n00b_obj_bundle_new();

    if (n00b_result_is_err(created)) {
        return nullptr;
    }

    n00b_obj_bundle_t *bundle  = n00b_result_get(created);
    n00b_buffer_t     *payload =
        n00b_buffer_from_cstr("macho-e2e-payload");

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

static n00b_string_t *
carrier_name(n00b_obj_bundle_carrier_t carrier)
{
    switch (carrier) {
    case N00B_OBJ_BUNDLE_CARRIER_METADATA:
        return r"METADATA";
    case N00B_OBJ_BUNDLE_CARRIER_LOADABLE:
        return r"LOADABLE";
    case N00B_OBJ_BUNDLE_CARRIER_SPLIT:
        return r"SPLIT";
    default:
        return r"AUTO";
    }
}

// Drive the neutral core for one carrier kind, asserting only neutral
// accessors. `id_prefix` distinguishes the per-carrier matrix rows in output.
static void
drive_carrier(n00b_buffer_t            *target,
              n00b_obj_bundle_carrier_t carrier,
              const char               *id_prefix)
{
    n00b_string_t     *cname  = carrier_name(carrier);
    n00b_obj_bundle_t *bundle = make_test_bundle();

    N00B_TEST_REQUIRE(bundle != nullptr);

    // Write the Mach-O carrier through the neutral public API.
    auto written = n00b_obj_bundle_write(target, bundle, .carrier = carrier);

    if (n00b_result_is_err(written)) {
        printf("  [FAIL] %s %s: n00b_obj_bundle_write failed\n",
               id_prefix,
               (char *)cname->data);
        g_fail++;
        return;
    }

    n00b_buffer_t *carrier_object = n00b_result_get(written);

    N00B_TEST_REQUIRE(carrier_object != nullptr);
    N00B_TEST_REQUIRE(carrier_object->byte_len > 0);

    // Read the carrier back through the neutral (auto-detecting) reader. The
    // read-back bundle reflects exactly what the carrier stored, so the
    // exec-plan / extract observations below are genuine per-carrier facts.
    auto read = n00b_obj_bundle_read(carrier_object);

    if (n00b_result_is_err(read)) {
        printf("  [FAIL] %s %s: n00b_obj_bundle_read failed\n",
               id_prefix,
               (char *)cname->data);
        g_fail++;
        return;
    }

    n00b_obj_bundle_t *read_bundle = n00b_result_get(read);

    N00B_TEST_REQUIRE(read_bundle != nullptr);

    // ---- exec plan (pure; no spawn) -------------------------------------
    auto plan_r = n00b_obj_bundle_exec_plan(read_bundle);

    if (n00b_result_is_err(plan_r)) {
        printf("  [FAIL] %s %s: n00b_obj_bundle_exec_plan failed\n",
               id_prefix,
               (char *)cname->data);
        g_fail++;
        return;
    }

    n00b_obj_bundle_exec_plan_t *plan = n00b_result_get(plan_r);

    N00B_TEST_REQUIRE(plan != nullptr);

    // resolved_mode must be a real resolved mode (AUTO resolves to EXTRACTED
    // per the documented contract), never an undefined value.
    n00b_obj_bundle_exec_mode_t resolved =
        n00b_obj_bundle_exec_plan_resolved_mode(plan);

    CHECK("resolved_mode is EXTRACTED (well-formed, non-AUTO)",
          resolved == N00B_OBJ_BUNDLE_EXEC_EXTRACTED);

    // selected_artifact_id must be populated for a bundle with a default exec.
    auto artifact_id = n00b_obj_bundle_exec_plan_selected_artifact_id(plan);

    CHECK("selected_artifact_id is set", n00b_option_is_set(artifact_id));

    // platform_support must be a host-neutral SUPPORTED/UNSUPPORTED value
    // (UNSUPPORTED is acceptable, e.g. on Linux): never NONE/error.
    n00b_obj_bundle_exec_platform_support_t support =
        n00b_obj_bundle_exec_plan_platform_support(plan);

    CHECK("platform_support is SUPPORTED or UNSUPPORTED (host-neutral)",
          support == N00B_OBJ_BUNDLE_EXEC_PLATFORM_SUPPORTED
              || support == N00B_OBJ_BUNDLE_EXEC_PLATFORM_UNSUPPORTED);

    // requires_extraction: assert the ACTUAL observed value and report it, so
    // any divergence from the planning guess is visible in the test log.
    bool requires_extraction =
        n00b_obj_bundle_exec_plan_requires_extraction(plan);

    printf("  [INFO] %s %s: requires_extraction=%s platform_support=%s\n",
           id_prefix,
           (char *)cname->data,
           requires_extraction ? "true" : "false",
           support == N00B_OBJ_BUNDLE_EXEC_PLATFORM_SUPPORTED
               ? "SUPPORTED"
               : "UNSUPPORTED");

    // The neutral exec-plan requires extraction for a bundle with a default
    // executable REGARDLESS of carrier kind (it does not branch on the Mach-O
    // carrier) — itself FR-23 evidence. Assert the actual landed contract
    // directly; this fails if the neutral pipeline ever stops requiring
    // extraction for such a bundle (it is NOT a tautology against `resolved`).
    CHECK("requires_extraction is true (neutral core, carrier-independent)",
          requires_extraction == true);

    // ---- extract: validate-only (no filesystem side effects) ------------
    n00b_string_t *vroot = r"n00b_macho_e2e_validate_root";
    auto           validate_r = n00b_obj_bundle_extract(
        read_bundle,
        vroot,
        .policy_mode = N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);

    if (n00b_result_is_err(validate_r)) {
        printf("  [FAIL] %s %s: validate-only extract failed\n",
               id_prefix,
               (char *)cname->data);
        g_fail++;
        return;
    }

    n00b_obj_bundle_extract_result_t *vfacts = n00b_result_get(validate_r);

    N00B_TEST_REQUIRE(vfacts != nullptr);
    CHECK("validate-only: destination_root populated",
          n00b_obj_bundle_extract_result_destination_root(vfacts) != nullptr);
    CHECK("validate-only: files_planned >= 1",
          n00b_obj_bundle_extract_result_files_planned(vfacts) >= 1);

    // ---- extract: default atomic path to a fresh temp root --------------
    // Use n00b_new_temp_path (does NOT pre-create the directory): atomic
    // extraction stages to a temp tree then commits to destination_root, so a
    // pre-existing root would collide on commit. This mirrors the ELF carrier
    // extract precedent (test_objfile_obj_bundle_carrier.c).
    n00b_string_t *root =
        n00b_new_temp_path(r"n00b_macho_e2e_", r"_root");

    auto extract_r = n00b_obj_bundle_extract(read_bundle, root);

    if (n00b_result_is_err(extract_r)) {
        n00b_obj_bundle_error_t *error =
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *, extract_r);
        auto message = n00b_obj_bundle_error_message(error);
        auto logical = n00b_obj_bundle_error_logical_path(error);
        auto destination = n00b_obj_bundle_error_destination_path(error);
        fprintf(stderr,
                "  [FAIL] %s %s: atomic extract failed code=%d "
                "message=%s logical=%s destination=%s\n",
                id_prefix,
                (char *)cname->data,
                (int)n00b_obj_bundle_error_code(error),
                n00b_option_is_set(message)
                    ? n00b_option_get(message)->data
                    : "(none)",
                n00b_option_is_set(logical)
                    ? n00b_option_get(logical)->data
                    : "(none)",
                n00b_option_is_set(destination)
                    ? n00b_option_get(destination)->data
                    : "(none)");
        g_fail++;
        return;
    }

    n00b_obj_bundle_extract_result_t *facts = n00b_result_get(extract_r);

    N00B_TEST_REQUIRE(facts != nullptr);
    CHECK("atomic: destination_root populated",
          n00b_obj_bundle_extract_result_destination_root(facts) != nullptr);
    CHECK("atomic: files_written >= 1",
          n00b_obj_bundle_extract_result_files_written(facts) >= 1);

    // overwrite fact must match the kwarg default (false).
    CHECK("atomic: overwrite fact matches kwarg default (false)",
          n00b_obj_bundle_extract_result_overwrite(facts) == false);

    (void)n00b_path_remove_tree(root, .ignore_missing = true);
}

// P1-a..e: structural e2e over each carrier kind via the neutral core only.
static void
test_macho_e2e_all_carriers(void)
{
    n00b_buffer_t *target = load_target_bytes();

    if (target == nullptr) {
        printf("  [FAIL] e2e: unsigned arm64 fixture unavailable\n");
        g_fail++;
        return;
    }

    // P1-a: METADATA. P1-b: LOADABLE. P1-c: SPLIT. P1-d (validate-only) and
    // P1-e (FR-23 neutral-only reach) are exercised inside drive_carrier for
    // every kind.
    drive_carrier(target, N00B_OBJ_BUNDLE_CARRIER_METADATA, "P1-a");
    drive_carrier(target, N00B_OBJ_BUNDLE_CARRIER_LOADABLE, "P1-b");
    drive_carrier(target, N00B_OBJ_BUNDLE_CARRIER_SPLIT, "P1-c");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("== WP-012 Phase 1: Mach-O always-run structural e2e ==\n");
    test_macho_e2e_all_carriers();

    printf("== e2e summary: %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}

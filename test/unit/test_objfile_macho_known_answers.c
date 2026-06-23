/**
 * @file test_objfile_macho_known_answers.c
 * @brief WP-012 Phase 2 always-run, host-neutral KNOWN-ANSWER test for the
 *        Mach-O object-bundle pipeline (FR-23 / NFR-10 evidence).
 *
 * Where the Phase-1 e2e (`test_objfile_macho_e2e.c`) asserts only "well-formed
 * / >= 1" shapes, this test FREEZES the EXACT deterministic outputs of the
 * format-neutral extract / exec-plan core for a fixed single-artifact bundle
 * carried by each of the three Mach-O carriers (METADATA / LOADABLE / SPLIT).
 * It builds the identical bundle the Phase-1 e2e builds (logical path
 * "bin/tool", a fixed payload, mode 0755, default exec = "bin/tool"), writes a
 * real Mach-O carrier into the committed unsigned arm64 fixture via the public
 * neutral `n00b_obj_bundle_write`, reads it back through the neutral
 * `n00b_obj_bundle_read`, and then drives ONLY the format-neutral
 * `n00b_obj_bundle_*` surface + neutral accessors (FR-23). No loader, no
 * codesign, no posix_spawn/fork/exec: deterministic on Linux as well as
 * un-gated macOS (D-006 / NFR-06).
 *
 * PROVENANCE (which known-answer case maps to which Phase-1 e2e carrier case):
 *   - KA-METADATA  ↔  Phase-1 P1-a (METADATA carrier, drive_carrier)
 *   - KA-LOADABLE  ↔  Phase-1 P1-b (LOADABLE carrier, drive_carrier)
 *   - KA-SPLIT     ↔  Phase-1 P1-c (SPLIT carrier, drive_carrier)
 * The Phase-1 e2e already proved these shapes are stable/well-formed; this
 * Phase-2 test promotes them to EXACT frozen values.
 *
 * EXPECTED CROSS-CARRIER SAMENESS (the point — FR-23 evidence): the neutral
 * `n00b_obj_bundle_exec_plan` / `n00b_obj_bundle_extract` core resolves the
 * SAME values for all three carriers, because it operates on the canonical
 * read-back bundle and does NOT branch on the Mach-O carrier kind. The
 * Phase-1 finding (verified against landed code): exec-plan resolves
 * AUTO→EXTRACTED and sets requires_extraction == true for a default-exec
 * bundle REGARDLESS of carrier. So the frozen known answers below are EXPECTED
 * IDENTICAL across the three carriers; that identity IS the FR-23 result.
 *
 * Frozen (deterministic) values, identical across all three carriers:
 *   - exec-plan resolved_mode           == N00B_OBJ_BUNDLE_EXEC_EXTRACTED
 *   - exec-plan requires_extraction     == true
 *   - exec-plan selected_logical_path   == "bin/tool" (the bundle's only exec)
 *   - validate-only files_planned       == 1   (== the bundle's artifact count)
 *   - validate-only directories_planned == 0   (single flat artifact, no dirs)
 *
 * Asserted as SHAPE rather than frozen (NOT a stable exact value):
 *   - selected_artifact_id: asserted SET only. The artifact id is assigned by
 *     the bundle model and is not a contract-guaranteed constant across
 *     encode/decode + allocator state, so freezing an exact integer would be
 *     over-promotion. Its presence (option set) IS deterministic.
 *   - policy_kind / policy_scope (validate-only): this bundle declares NO
 *     policy, so the neutral core may legitimately leave these unset; we assert
 *     they are well-formed options (set ⇒ a defined enum member) rather than
 *     freezing a specific kind/scope. This avoids over-promoting an
 *     unstable/optional field.
 *
 * Per n00b-api-guidelines § 1 / macwrap DECISIONS.md D-018, this test-local
 * scaffolding may use header-only libc for path assembly (`snprintf`,
 * `getenv`); every code-under-test call uses the n00b surface.
 *
 * Cases KA-a..KA-c (one per carrier) per the Phase 2 regression matrix.
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
#include "text/strings/string_ops.h"
#include "compiler/objfile/bstream.h"
#include "compiler/objfile/obj_bundle.h"

#define N00B_TEST_REQUIRE(expr) n00b_require((expr), #expr)

#define TEST_FIXTURE_UNSIGNED "test/unit/data/hello_unsigned_arm64.macho"

// Frozen known answers (see file header for the determinism rationale). The
// expected selected logical path is the literal r"bin/tool" inlined at the
// comparison site (rstr literals do not compose via macro concatenation).
#define KA_EXPECTED_FILES_PLANNED     1u
#define KA_EXPECTED_DIRS_PLANNED      0u

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
// Fixture loading (mirror test_objfile_macho_e2e.c:load_target_bytes).
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

// Build the SAME single-artifact bundle the Phase-1 e2e builds, so the frozen
// known answers correspond exactly to that proven structural case.
static n00b_obj_bundle_t *
make_test_bundle(void)
{
    auto created = n00b_obj_bundle_new();

    if (n00b_result_is_err(created)) {
        return nullptr;
    }

    n00b_obj_bundle_t *bundle  = n00b_result_get(created);
    n00b_buffer_t     *payload =
        n00b_buffer_from_cstr("macho-known-answer-payload");

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

// Drive the neutral core for one carrier kind and assert the EXACT frozen
// known answers. `id_prefix` distinguishes the matrix rows in output.
static void
freeze_carrier(n00b_buffer_t            *target,
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

    // Read the carrier back through the neutral (auto-detecting) reader.
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

    // ---- exec plan (pure; no spawn): EXACT frozen answers ---------------
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

    // FROZEN: AUTO resolves to EXTRACTED (carrier-independent neutral core).
    n00b_obj_bundle_exec_mode_t resolved =
        n00b_obj_bundle_exec_plan_resolved_mode(plan);

    CHECK("exec-plan resolved_mode == EXTRACTED (frozen)",
          resolved == N00B_OBJ_BUNDLE_EXEC_EXTRACTED);

    // FROZEN: a default-exec bundle requires extraction, carrier-independent.
    bool requires_extraction =
        n00b_obj_bundle_exec_plan_requires_extraction(plan);

    CHECK("exec-plan requires_extraction == true (frozen)",
          requires_extraction == true);

    // FROZEN: the selected target is the bundle's only executable, "bin/tool".
    auto selected_path_opt =
        n00b_obj_bundle_exec_plan_selected_logical_path(plan);

    CHECK("exec-plan selected_logical_path is set",
          n00b_option_is_set(selected_path_opt));

    if (n00b_option_is_set(selected_path_opt)) {
        n00b_string_t *selected_path = n00b_option_get(selected_path_opt);

        // The option is set, so n00b_option_get returns the stored (non-null)
        // path; compare the frozen exact value directly.
        CHECK("exec-plan selected_logical_path == \"bin/tool\" (frozen)",
              n00b_unicode_str_eq(selected_path, r"bin/tool"));
    }
    else {
        // Already counted the failure above; keep matrix-row count stable.
        CHECK("exec-plan selected_logical_path == \"bin/tool\" (frozen)",
              false);
    }

    // SHAPE (not frozen): artifact id is allocator/model-assigned, not a
    // contract constant; assert presence only (see file header).
    auto artifact_id_opt =
        n00b_obj_bundle_exec_plan_selected_artifact_id(plan);

    CHECK("exec-plan selected_artifact_id is set (shape, not frozen)",
          n00b_option_is_set(artifact_id_opt));

    // ---- extract: VALIDATE-ONLY (no filesystem side effects) ------------
    // files_written is 0 in validate-only mode, so we freeze files_planned.
    n00b_string_t *vroot = r"n00b_macho_ka_validate_root";
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

    // FROZEN: exactly one regular/executable file is planned (1 artifact).
    uint64_t files_planned =
        n00b_obj_bundle_extract_result_files_planned(vfacts);

    CHECK("validate-only files_planned == 1 (frozen, == artifact count)",
          files_planned == KA_EXPECTED_FILES_PLANNED);

    // FROZEN: the single flat artifact "bin/tool" plans zero directories.
    uint64_t directories_planned =
        n00b_obj_bundle_extract_result_directories_planned(vfacts);

    CHECK("validate-only directories_planned == 0 (frozen)",
          directories_planned == KA_EXPECTED_DIRS_PLANNED);

    // FROZEN: validate-only writes nothing to disk.
    CHECK("validate-only files_written == 0 (frozen, no disk writes)",
          n00b_obj_bundle_extract_result_files_written(vfacts) == 0);

    // FROZEN: the validate-only result echoes the requested policy mode.
    CHECK("validate-only result policy_mode == VALIDATE_ONLY (frozen)",
          n00b_obj_bundle_extract_result_policy_mode(vfacts)
              == N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);

    // SHAPE (not frozen): this bundle declares no policy, so policy_kind /
    // policy_scope may legitimately be unset; assert only that, if set, the
    // option is well-formed (see file header). Reading them must not crash.
    auto policy_kind_opt =
        n00b_obj_bundle_extract_result_policy_kind(vfacts);
    auto policy_scope_opt =
        n00b_obj_bundle_extract_result_policy_scope(vfacts);

    bool policy_kind_wellformed = true;
    if (n00b_option_is_set(policy_kind_opt)) {
        n00b_obj_bundle_policy_kind_t k = n00b_option_get(policy_kind_opt);
        policy_kind_wellformed =
            (k == N00B_OBJ_BUNDLE_POLICY_KIND_NONE
             || k == N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT
             || k == N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1
             || k == N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B);
    }
    CHECK("validate-only policy_kind option well-formed (shape, not frozen)",
          policy_kind_wellformed);

    bool policy_scope_wellformed = true;
    if (n00b_option_is_set(policy_scope_opt)) {
        n00b_obj_bundle_policy_scope_t s = n00b_option_get(policy_scope_opt);
        policy_scope_wellformed =
            (s == N00B_OBJ_BUNDLE_POLICY_SCOPE_NONE
             || s == N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION
             || s == N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION
             || s == N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH);
    }
    CHECK("validate-only policy_scope option well-formed (shape, not frozen)",
          policy_scope_wellformed);
}

// KA-a..c: freeze the neutral-core known answers for each carrier kind. The
// frozen values are EXPECTED IDENTICAL across all three (FR-23): the neutral
// core does not branch on the Mach-O carrier.
static void
test_macho_known_answers_all_carriers(void)
{
    n00b_buffer_t *target = load_target_bytes();

    if (target == nullptr) {
        printf("  [FAIL] known-answers: unsigned arm64 fixture unavailable\n");
        g_fail++;
        return;
    }

    freeze_carrier(target, N00B_OBJ_BUNDLE_CARRIER_METADATA, "KA-a");
    freeze_carrier(target, N00B_OBJ_BUNDLE_CARRIER_LOADABLE, "KA-b");
    freeze_carrier(target, N00B_OBJ_BUNDLE_CARRIER_SPLIT, "KA-c");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("== WP-012 Phase 2: Mach-O always-run known-answer tests ==\n");
    test_macho_known_answers_all_carriers();

    printf("== known-answers summary: %d passed, %d failed ==\n",
           g_pass,
           g_fail);
    return g_fail == 0 ? 0 : 1;
}

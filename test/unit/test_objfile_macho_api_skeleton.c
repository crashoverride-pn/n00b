/**
 * @file test_objfile_macho_api_skeleton.c
 * @brief Umbrella-init / header-skeleton regression for the Mach-O rewrite-stack
 *        API headers (WP-002 Phase 1, §6.5b / D-014).
 *
 * This test includes the four compiling API headers landed by WP-002 (the
 * Phase-1 rewrite-stack trio plus the Phase-2 carrier header) directly (they are
 * NOT pulled in via the n00b.h umbrella), so it catches header-include-path and
 * meson-wiring regressions: if any of the four headers stops compiling, or the
 * meson `objfile_test_names` wiring drops this target, the build fails here. It
 * also pins the public struct sizes and every error-block constant with
 * `static_assert`, so an accidental reorder/renumber is caught at compile time.
 *
 * No runtime behavior is exercised (the function bodies are filled by WP-003+).
 * Host-neutral: no Darwin/codesign gate.
 */
#include <stdio.h>
#include <assert.h>

#include "n00b.h"
#include "compiler/objfile/macho_layout.h"
#include "compiler/objfile/macho_rewrite_admit.h"
#include "compiler/objfile/macho_rewrite.h"
#include "compiler/objfile/macho_carrier.h"

// ============================================================================
// §1 layout — pinned struct sizes + error block (-4201..-4203)
// ============================================================================

static_assert(sizeof(n00b_macho_layout_interval_t) > 0,
              "macho layout interval struct must be a complete type");
static_assert(sizeof(n00b_macho_layout_coverage_t) > 0,
              "macho layout coverage struct must be a complete type");
static_assert(sizeof(n00b_macho_layout_interval_list_t) > 0,
              "macho layout interval-list struct must be a complete type");
static_assert(sizeof(n00b_macho_layout_collision_t) > 0,
              "macho layout collision struct must be a complete type");
static_assert(sizeof(n00b_macho_layout_gap_t) > 0,
              "macho layout gap struct must be a complete type");
static_assert(sizeof(n00b_macho_layout_t) > 0,
              "macho layout root struct must be a complete type");

static_assert(N00B_MACHO_LAYOUT_OK == 0, "layout OK code");
static_assert(N00B_MACHO_LAYOUT_ERR_INVALID == -4201, "layout error block base");
static_assert(N00B_MACHO_LAYOUT_ERR_OVERFLOW == -4202, "layout error block");
static_assert(N00B_MACHO_LAYOUT_ERR_INTERVAL == -4203, "layout error block end");

static_assert(N00B_MACHO_ARM64_PAGE_SIZE == 0x4000u,
              "arm64 page-size convenience constant (OQ-4 home)");

// ============================================================================
// §2 admit — pinned struct sizes + error block (-3901..-3905)
// ============================================================================

static_assert(sizeof(n00b_macho_rewrite_admit_policy_t) > 0,
              "macho admit policy struct must be a complete type");
static_assert(sizeof(n00b_macho_rewrite_admit_metadata_request_t) > 0,
              "macho admit metadata-request struct must be a complete type");
static_assert(sizeof(n00b_macho_rewrite_admit_loadable_request_t) > 0,
              "macho admit loadable-request struct must be a complete type");
static_assert(sizeof(n00b_macho_rewrite_admit_placement_t) > 0,
              "macho admit placement struct must be a complete type");
static_assert(sizeof(n00b_macho_rewrite_admit_result_t) > 0,
              "macho admit result struct must be a complete type");
static_assert(sizeof(n00b_macho_rewrite_admit_loadable_result_t) > 0,
              "macho admit loadable-result struct must be a complete type");
static_assert(sizeof(n00b_macho_rewrite_admit_entrypoint_request_t) > 0,
              "macho admit entrypoint-request struct must be a complete type");
static_assert(sizeof(n00b_macho_rewrite_admit_entrypoint_result_t) > 0,
              "macho admit entrypoint-result struct must be a complete type");

static_assert(N00B_MACHO_REWRITE_ADMIT_OK == 0, "admit OK code");
static_assert(N00B_MACHO_REWRITE_ADMIT_ERR_NULL_BINARY == -3901,
              "admit error block base");
static_assert(N00B_MACHO_REWRITE_ADMIT_ERR_NULL_REQUEST == -3902,
              "admit error block");
static_assert(N00B_MACHO_REWRITE_ADMIT_ERR_ZERO_PAYLOAD == -3903,
              "admit error block");
static_assert(N00B_MACHO_REWRITE_ADMIT_ERR_LAYOUT_SUBSTRATE == -3904,
              "admit error block");
static_assert(N00B_MACHO_REWRITE_ADMIT_ERR_OVERFLOW == -3905,
              "admit error block end");

// ============================================================================
// §3 rewrite — pinned struct sizes + error block (-4401..-4415)
// ============================================================================

static_assert(sizeof(n00b_macho_rewrite_metadata_request_t) > 0,
              "macho rewrite metadata-request struct must be a complete type");
static_assert(sizeof(n00b_macho_rewrite_loadable_request_t) > 0,
              "macho rewrite loadable-request struct must be a complete type");
static_assert(sizeof(n00b_macho_rewrite_target_profile_t) > 0,
              "macho rewrite target-profile struct must be a complete type");
static_assert(sizeof(n00b_macho_rewrite_patch_t) > 0,
              "macho rewrite patch struct must be a complete type");
static_assert(sizeof(n00b_macho_rewrite_plan_t) > 0,
              "macho rewrite plan struct must be a complete type");
static_assert(sizeof(n00b_macho_rewrite_loadable_plan_t) > 0,
              "macho rewrite loadable-plan struct must be a complete type");
static_assert(sizeof(n00b_macho_rewrite_host_entrypoint_target_t) > 0,
              "macho rewrite host-entrypoint-target struct must be a complete type");

static_assert(N00B_MACHO_REWRITE_OK == 0, "rewrite OK code");
static_assert(N00B_MACHO_REWRITE_ERR_NULL_BINARY == -4401,
              "rewrite error block base");
static_assert(N00B_MACHO_REWRITE_ERR_NULL_REQUEST == -4402, "rewrite error block");
static_assert(N00B_MACHO_REWRITE_ERR_NULL_NOTE_OWNER == -4403,
              "rewrite error block");
static_assert(N00B_MACHO_REWRITE_ERR_NULL_PAYLOAD == -4404, "rewrite error block");
static_assert(N00B_MACHO_REWRITE_ERR_ZERO_PAYLOAD == -4405, "rewrite error block");
static_assert(N00B_MACHO_REWRITE_ERR_TARGET_PROFILE == -4406,
              "rewrite error block");
static_assert(N00B_MACHO_REWRITE_ERR_ADMISSION == -4407, "rewrite error block");
static_assert(N00B_MACHO_REWRITE_ERR_OVERFLOW == -4408, "rewrite error block");
static_assert(N00B_MACHO_REWRITE_ERR_NULL_PLAN == -4409, "rewrite error block");
static_assert(N00B_MACHO_REWRITE_ERR_PLAN_REJECTED == -4410, "rewrite error block");
static_assert(N00B_MACHO_REWRITE_ERR_UNSUPPORTED_PLAN == -4411,
              "rewrite error block");
static_assert(N00B_MACHO_REWRITE_ERR_APPLY == -4412, "rewrite error block");
static_assert(N00B_MACHO_REWRITE_ERR_PARSE_AFTER_APPLY == -4413,
              "rewrite error block");
static_assert(N00B_MACHO_REWRITE_ERR_NOTE_NOT_FOUND == -4414,
              "rewrite error block");
static_assert(N00B_MACHO_REWRITE_ERR_TRUSTED_NAME == -4415,
              "rewrite error block end");

// ============================================================================
// §4 carrier descriptor — pinned struct sizes + size constants + error block
//     (-4101..-4109)
// ============================================================================

static_assert(sizeof(n00b_macho_carrier_split_record_t) > 0,
              "macho carrier split-record struct must be a complete type");
static_assert(sizeof(n00b_macho_carrier_descriptor_t) > 0,
              "macho carrier descriptor struct must be a complete type");

// The split aux record must match its fixed 48-byte on-disk layout (§4.1).
static_assert(sizeof(n00b_macho_carrier_split_record_t)
                  == N00B_MACHO_CARRIER_RECORD_SIZE,
              "split aux record must be exactly 48 bytes on-disk");

// The four pinned size constants (§4.2).
static_assert(N00B_MACHO_CARRIER_MAGIC_LEN == 8u, "carrier magic length");
static_assert(N00B_MACHO_CARRIER_HEADER_SIZE == 64u, "carrier header size");
static_assert(N00B_MACHO_CARRIER_RECORD_SIZE == 48u, "carrier record size");
static_assert(N00B_MACHO_CARRIER_DIGEST_LEN == 32u, "carrier digest length");

// Version + carrier-kind enum (§4.2).
static_assert(N00B_MACHO_CARRIER_MAJOR == 1u, "carrier major version");
static_assert(N00B_MACHO_CARRIER_MINOR == 0u, "carrier minor version");
static_assert(N00B_MACHO_CARRIER_KIND_LOADABLE == 1, "carrier kind loadable");
static_assert(N00B_MACHO_CARRIER_KIND_SPLIT == 2, "carrier kind split");

static_assert(N00B_MACHO_CARRIER_OK == 0, "carrier OK code");
static_assert(N00B_MACHO_CARRIER_ERR_NULL_INPUT == -4101,
              "carrier error block base");
static_assert(N00B_MACHO_CARRIER_ERR_SHORT_HEADER == -4102,
              "carrier error block");
static_assert(N00B_MACHO_CARRIER_ERR_BAD_MAGIC == -4103, "carrier error block");
static_assert(N00B_MACHO_CARRIER_ERR_BAD_VERSION == -4104,
              "carrier error block");
static_assert(N00B_MACHO_CARRIER_ERR_BAD_HEADER_SIZE == -4105,
              "carrier error block");
static_assert(N00B_MACHO_CARRIER_ERR_BAD_KIND == -4106, "carrier error block");
static_assert(N00B_MACHO_CARRIER_ERR_BOUNDS == -4107, "carrier error block");
static_assert(N00B_MACHO_CARRIER_ERR_DIGEST == -4108, "carrier error block");
static_assert(N00B_MACHO_CARRIER_ERR_RECORD_COUNT == -4109,
              "carrier error block");
static_assert(N00B_MACHO_CARRIER_ERR_UNSUPPORTED_CARRIER == -4110,
              "carrier error block end");
// D-040: the SPLIT skeleton is a contiguous LC_NOTE-trailer blob (NO skeleton
// record), so the former SKELETON_ARTIFACT sentinel is removed; the trailer adds
// the skeleton_len + record_count words (16 bytes) after the shared header.
static_assert(N00B_MACHO_CARRIER_SPLIT_TRAILER_SIZE == 16u,
              "carrier SPLIT trailer prefix (skeleton_len + record_count)");

// ============================================================================
// Phase-0 constant the rewrite-stack API reads (sanity).
// ============================================================================

static_assert(N00B_MACHO_HEADER_64_SIZE == 32u,
              "mach_header_64 on-disk size");

int
main(void)
{
    // All checks are compile-time static_asserts above; reaching main proves
    // the four headers compiled together and the target was built + wired.
    printf("All MachO API skeleton checks passed.\n");
    return 0;
}

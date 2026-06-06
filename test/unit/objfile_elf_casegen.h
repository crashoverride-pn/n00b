/**
 * @file objfile_elf_casegen.h
 * @brief Test-local ELF64 fixture generator for object-file known answers.
 *
 * Generates small synthetic ELF byte buffers for parser and future strict
 * rewrite-admission tests. The helpers are intentionally local to unit tests;
 * production layout analysis should live under `compiler/objfile/`.
 *
 * Related modules:
 * - `compiler/objfile/elf.h` for the parser under test.
 * - `adt/interval_tree.h` for the existing interval tree that later layout
 *   admission work should reuse.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "n00b.h"
#include "core/buffer.h"
#include "compiler/objfile/elf_rewrite_admit.h"
#include "compiler/objfile/elf_rewrite.h"
#include "compiler/objfile/elf_types.h"

#define N00B_TEST_ELF_E_PHOFF        32
#define N00B_TEST_ELF_E_SHOFF        40
#define N00B_TEST_ELF_E_EHSIZE       52
#define N00B_TEST_ELF_E_PHENTSIZE    54
#define N00B_TEST_ELF_E_PHNUM        56
#define N00B_TEST_ELF_E_SHENTSIZE    58
#define N00B_TEST_ELF_E_SHNUM        60
#define N00B_TEST_ELF_E_SHSTRNDX     62
#define N00B_TEST_ELF_SH_NAME        0
#define N00B_TEST_ELF_SH_TYPE        4
#define N00B_TEST_ELF_SH_OFFSET      24
#define N00B_TEST_ELF_SH_SIZE        32
#define N00B_TEST_ELF_SHSTRTAB_SH    320
#define N00B_TEST_ELF_PHDR_P_MEMSZ   40
#define N00B_TEST_ELF_SHN_LORESERVE  0xff00u
#define N00B_TEST_ELF_PN_XNUM        0xffffu

typedef enum {
    N00B_TEST_ELF_CASE_KNOWN,
    N00B_TEST_ELF_CASE_EXPLORE,
    N00B_TEST_ELF_CASE_PENDING,
    N00B_TEST_ELF_CASE_DIVERGE,
    N00B_TEST_ELF_CASE_RETIRED,
} n00b_test_elf_case_state_t;

typedef enum {
    N00B_TEST_ELF_PARSE_OK,
    N00B_TEST_ELF_PARSE_REJECT,
} n00b_test_elf_parse_expect_t;

typedef enum {
    N00B_TEST_ELF_ORACLE_NONE,
    N00B_TEST_ELF_ORACLE_READ_TARGET,
    N00B_TEST_ELF_ORACLE_PHTAB_ADJUSTMENT,
} n00b_test_elf_oracle_mode_t;

typedef enum {
    N00B_TEST_ELF_ORACLE_VALID_TARGET,
    N00B_TEST_ELF_ORACLE_INVALID_TARGET,
    N00B_TEST_ELF_ORACLE_PHTAB_ADJUSTABLE,
    N00B_TEST_ELF_ORACLE_PHTAB_NOT_ADJUSTABLE,
} n00b_test_elf_oracle_expect_t;

typedef enum {
    N00B_TEST_ELF_DIVERGENCE_SHARED_SCOPE,
    N00B_TEST_ELF_DIVERGENCE_N00B_BROADER,
    N00B_TEST_ELF_DIVERGENCE_BRANDON_NARROWER,
    N00B_TEST_ELF_DIVERGENCE_DIAGNOSTIC_ONLY,
} n00b_test_elf_divergence_t;

typedef enum {
    N00B_TEST_ELF_ADMISSION_NONE,
    N00B_TEST_ELF_ADMISSION_RELAXED_EOF,
    N00B_TEST_ELF_ADMISSION_STRICT_EOF,
    N00B_TEST_ELF_ADMISSION_RELAXED_PREFERRED_GAP,
    N00B_TEST_ELF_ADMISSION_RELAXED_OVERLAY_PRESERVE,
    N00B_TEST_ELF_ADMISSION_RELAXED_OVERLAY_APPEND,
} n00b_test_elf_admission_request_t;

typedef enum {
    N00B_TEST_ELF_TARGET_MUTATION_NONE,
    N00B_TEST_ELF_TARGET_MUTATION_INVALID_EHSIZE,
    N00B_TEST_ELF_TARGET_MUTATION_INVALID_SHENTSIZE,
    N00B_TEST_ELF_TARGET_MUTATION_INVALID_PHENTSIZE,
    N00B_TEST_ELF_TARGET_MUTATION_SHNUM_ZERO,
    N00B_TEST_ELF_TARGET_MUTATION_SHNUM_ONE,
    N00B_TEST_ELF_TARGET_MUTATION_SHNUM_LORESERVE,
    N00B_TEST_ELF_TARGET_MUTATION_SHNUM_XINDEX,
    N00B_TEST_ELF_TARGET_MUTATION_SHOFF_ZERO,
    N00B_TEST_ELF_TARGET_MUTATION_SHOFF_OUT_OF_BOUNDS,
    N00B_TEST_ELF_TARGET_MUTATION_SHOFF_WRAP,
    N00B_TEST_ELF_TARGET_MUTATION_SHSTRNDX_ZERO,
    N00B_TEST_ELF_TARGET_MUTATION_SHSTRNDX_LORESERVE,
    N00B_TEST_ELF_TARGET_MUTATION_SHSTRNDX_XINDEX,
    N00B_TEST_ELF_TARGET_MUTATION_SHSTRNDX_OUT_OF_RANGE,
    N00B_TEST_ELF_TARGET_MUTATION_SHSTRTAB_WRONG_TYPE,
    N00B_TEST_ELF_TARGET_MUTATION_SHSTRTAB_INVALID_SIZE,
    N00B_TEST_ELF_TARGET_MUTATION_SHSTRTAB_OFFSET_WRAP,
    N00B_TEST_ELF_TARGET_MUTATION_SECTION_NAME_INDEX,
    N00B_TEST_ELF_TARGET_MUTATION_PHNUM_ZERO,
    N00B_TEST_ELF_TARGET_MUTATION_PHNUM_XNUM,
    N00B_TEST_ELF_TARGET_MUTATION_PHOFF_WRAP,
    N00B_TEST_ELF_TARGET_MUTATION_EXISTING_RESERVED_SECTION_NAME,
} n00b_test_elf_target_mutation_t;

typedef enum {
    N00B_TEST_ELF_REWRITE_NONE,
    N00B_TEST_ELF_REWRITE_RELAXED_EOF,
    N00B_TEST_ELF_REWRITE_RELAXED_PREFERRED_GAP,
    N00B_TEST_ELF_REWRITE_RELAXED_OVERLAY_PRESERVE,
    N00B_TEST_ELF_REWRITE_RELAXED_OVERLAY_APPEND,
    N00B_TEST_ELF_REWRITE_RESERVED_REQUESTED_NAME,
} n00b_test_elf_rewrite_request_t;

typedef enum {
    N00B_TEST_ELF_LOADABLE_NONE,
    N00B_TEST_ELF_LOADABLE_DEFERRED,
    N00B_TEST_ELF_LOADABLE_IN_PLACE,
    N00B_TEST_ELF_LOADABLE_RELOCATE,
} n00b_test_elf_loadable_request_t;

#define N00B_TEST_ELF_ORACLE_CODE_PHTAB_ADJUST_MEMORY 43
#define N00B_TEST_ELF_ORACLE_CODE_PHTAB_ADJUST_FILE 44
#define N00B_TEST_ELF_ORACLE_CODE_PHTAB_ADJUST_EOF 56
#define N00B_TEST_ELF_ORACLE_CODE_PHTAB_ADJUST_NONZERO_SLACK 47

typedef enum {
    N00B_TEST_ELF_GEN_VALID_MINIMAL_EXEC,
    N00B_TEST_ELF_GEN_BAD_MAGIC,
    N00B_TEST_ELF_GEN_ELF32_INPUT,
    N00B_TEST_ELF_GEN_TRUNCATED_HEADER,
    N00B_TEST_ELF_GEN_PHTAB_NOT_IN_LOAD,
    N00B_TEST_ELF_GEN_ENTRY_OUTSIDE_LOAD,
    N00B_TEST_ELF_GEN_ENTRY_IN_MEM_NOT_FILE,
    N00B_TEST_ELF_GEN_PT_PHDR_BAD_SIZE,
    N00B_TEST_ELF_GEN_SHSTRTAB_NOT_TERMINATED,
    N00B_TEST_ELF_GEN_OVERLAY_AFTER_SEGMENTS,
    N00B_TEST_ELF_GEN_LAYOUT_CLASSIFICATION,
    N00B_TEST_ELF_GEN_LAYOUT_NONZERO_UNKNOWN,
    N00B_TEST_ELF_GEN_PHTAB_ADJUST_ACCEPTED,
    N00B_TEST_ELF_GEN_PHTAB_ADJUST_MEMORY_TAIL,
    N00B_TEST_ELF_GEN_PHTAB_ADJUST_MEMORY_COLLISION,
    N00B_TEST_ELF_GEN_PHTAB_ADJUST_FILE_COLLISION,
    N00B_TEST_ELF_GEN_PHTAB_ADJUST_NONZERO_SLACK,
    N00B_TEST_ELF_GEN_PHTAB_ADJUST_AT_EOF,
    N00B_TEST_ELF_GEN_LOADABLE_RELOCATE_DIRECT,
    N00B_TEST_ELF_GEN_LOADABLE_RELOCATE_OVERLAY,
    N00B_TEST_ELF_GEN_LOADABLE_RELOCATE_ADDRESS_OVERFLOW,
} n00b_test_elf_generator_t;

typedef struct {
    const char                     *name;
    n00b_test_elf_case_state_t      state;
    n00b_test_elf_generator_t       generator;
    n00b_test_elf_parse_expect_t    expect_parse;
    const char                     *expect_reason;
    n00b_test_elf_oracle_mode_t     oracle_mode;
    n00b_test_elf_oracle_expect_t   oracle_expect;
    bool                            has_oracle_code;
    int                             oracle_expected_code;
    n00b_test_elf_divergence_t      divergence;
    n00b_test_elf_target_mutation_t target_mutation;
    bool                            has_target_profile;
    n00b_elf_rewrite_target_profile_reason_t target_profile_reason;
    int                             target_profile_packager_errcode;
    n00b_test_elf_admission_request_t admission_request;
    n00b_elf_rewrite_admit_outcome_t  admission_outcome;
    n00b_elf_rewrite_admit_rejection_reason_t admission_reason;
    n00b_elf_rewrite_admit_placement_kind_t admission_placement;
    n00b_test_elf_rewrite_request_t rewrite_request;
    n00b_elf_rewrite_plan_outcome_t rewrite_outcome;
    n00b_elf_rewrite_rejection_reason_t rewrite_reason;
    n00b_elf_rewrite_admit_rejection_reason_t rewrite_admission_reason;
    n00b_elf_rewrite_admit_placement_kind_t rewrite_admission_placement;
    n00b_elf_rewrite_table_strategy_t rewrite_table_strategy;
    n00b_test_elf_loadable_request_t loadable_request;
    n00b_elf_rewrite_plan_outcome_t loadable_outcome;
    n00b_elf_rewrite_rejection_reason_t loadable_reason;
    n00b_elf_rewrite_admit_rejection_reason_t loadable_admission_reason;
    n00b_elf_rewrite_loadable_phtab_strategy_t loadable_phtab_strategy;
    n00b_elf_rewrite_loadable_phtab_adjust_status_t loadable_phtab_adjust_status;
    n00b_elf_rewrite_admit_rejection_reason_t loadable_phtab_adjust_reason;
    n00b_elf_rewrite_loadable_relocation_status_t loadable_relocation_status;
    n00b_elf_rewrite_rejection_reason_t loadable_relocation_reason;
    bool                            loadable_apply_reparse;
    const char                     *description;
} n00b_test_elf_case_t;

#define N00B_TEST_ELF_PROFILE_CASE(case_name, reason_name, mutation_value, profile_reason, errcode, text) \
    {                                                                                                    \
        .name          = case_name,                                                                     \
        .state         = N00B_TEST_ELF_CASE_KNOWN,                                                      \
        .generator     = N00B_TEST_ELF_GEN_VALID_MINIMAL_EXEC,                                          \
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,                                                        \
        .expect_reason = reason_name,                                                                   \
        .oracle_mode   = N00B_TEST_ELF_ORACLE_READ_TARGET,                                              \
        .oracle_expect = N00B_TEST_ELF_ORACLE_INVALID_TARGET,                                           \
        .has_oracle_code = true,                                                                        \
        .oracle_expected_code = errcode,                                                                \
        .divergence    = N00B_TEST_ELF_DIVERGENCE_SHARED_SCOPE,                                         \
        .target_mutation = mutation_value,                                                              \
        .has_target_profile = true,                                                                     \
        .target_profile_reason = profile_reason,                                                        \
        .target_profile_packager_errcode = errcode,                                                     \
        .description   = text,                                                                          \
    }

static const n00b_test_elf_case_t n00b_test_elf_cases[] = {
    {
        .name          = "phtab_adjust_accepted",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_PHTAB_ADJUST_ACCEPTED,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "phtab-adjust-accepted",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_PHTAB_ADJUSTMENT,
        .oracle_expect = N00B_TEST_ELF_ORACLE_PHTAB_ADJUSTABLE,
        .has_oracle_code = true,
        .oracle_expected_code = 0,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_DIAGNOSTIC_ONLY,
        .loadable_request = N00B_TEST_ELF_LOADABLE_IN_PLACE,
        .loadable_outcome = N00B_ELF_REWRITE_PLAN_ACCEPTED,
        .loadable_reason = N00B_ELF_REWRITE_REJECT_NONE,
        .loadable_admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
        .loadable_phtab_strategy =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST,
        .loadable_phtab_adjust_status =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_ACCEPTED,
        .loadable_apply_reparse = true,
        .description   = "In-place PHTAB growth fits before the next object.",
    },
    {
        .name          = "phtab_adjust_memory_tail",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_PHTAB_ADJUST_MEMORY_TAIL,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "phtab-adjust-memory-tail",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_PHTAB_ADJUSTMENT,
        .oracle_expect = N00B_TEST_ELF_ORACLE_PHTAB_ADJUSTABLE,
        .has_oracle_code = true,
        .oracle_expected_code = 0,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_DIAGNOSTIC_ONLY,
        .loadable_request = N00B_TEST_ELF_LOADABLE_IN_PLACE,
        .loadable_outcome = N00B_ELF_REWRITE_PLAN_ACCEPTED,
        .loadable_reason = N00B_ELF_REWRITE_REJECT_NONE,
        .loadable_admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
        .loadable_phtab_strategy =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST,
        .loadable_phtab_adjust_status =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_ACCEPTED,
        .description   = "In-place PHTAB growth preserves a memory-only tail.",
    },
    {
        .name          = "phtab_adjust_memory_collision",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_PHTAB_ADJUST_MEMORY_COLLISION,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "phtab-adjust-memory-collision",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_PHTAB_ADJUSTMENT,
        .oracle_expect = N00B_TEST_ELF_ORACLE_PHTAB_NOT_ADJUSTABLE,
        .has_oracle_code = true,
        .oracle_expected_code = N00B_TEST_ELF_ORACLE_CODE_PHTAB_ADJUST_MEMORY,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_DIAGNOSTIC_ONLY,
        .loadable_request = N00B_TEST_ELF_LOADABLE_IN_PLACE,
        .loadable_outcome = N00B_ELF_REWRITE_PLAN_ACCEPTED,
        .loadable_reason = N00B_ELF_REWRITE_REJECT_NONE,
        .loadable_admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
        .loadable_phtab_strategy =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE,
        .loadable_phtab_adjust_status =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_RELOCATABLE,
        .loadable_phtab_adjust_reason =
            N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_MEMORY_COLLISION,
        .loadable_relocation_status =
            N00B_ELF_REWRITE_LOADABLE_RELOCATION_ACCEPTED,
        .loadable_relocation_reason = N00B_ELF_REWRITE_REJECT_NONE,
        .description   = "Address collision blocks in-place growth; relocation is safe.",
    },
    {
        .name          = "phtab_adjust_file_collision",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_PHTAB_ADJUST_FILE_COLLISION,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "phtab-adjust-file-collision",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_PHTAB_ADJUSTMENT,
        .oracle_expect = N00B_TEST_ELF_ORACLE_PHTAB_NOT_ADJUSTABLE,
        .has_oracle_code = true,
        .oracle_expected_code = N00B_TEST_ELF_ORACLE_CODE_PHTAB_ADJUST_FILE,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_DIAGNOSTIC_ONLY,
        .loadable_request = N00B_TEST_ELF_LOADABLE_IN_PLACE,
        .loadable_outcome = N00B_ELF_REWRITE_PLAN_ACCEPTED,
        .loadable_reason = N00B_ELF_REWRITE_REJECT_NONE,
        .loadable_admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
        .loadable_phtab_strategy =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE,
        .loadable_phtab_adjust_status =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_RELOCATABLE,
        .loadable_phtab_adjust_reason =
            N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_FILE_COLLISION,
        .loadable_relocation_status =
            N00B_ELF_REWRITE_LOADABLE_RELOCATION_ACCEPTED,
        .loadable_relocation_reason = N00B_ELF_REWRITE_REJECT_NONE,
        .description   = "File collision blocks in-place growth; relocation is safe.",
    },
    {
        .name          = "phtab_adjust_nonzero_slack",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_PHTAB_ADJUST_NONZERO_SLACK,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "phtab-adjust-nonzero-slack",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_PHTAB_ADJUSTMENT,
        .oracle_expect = N00B_TEST_ELF_ORACLE_PHTAB_NOT_ADJUSTABLE,
        .has_oracle_code = true,
        .oracle_expected_code = N00B_TEST_ELF_ORACLE_CODE_PHTAB_ADJUST_NONZERO_SLACK,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_DIAGNOSTIC_ONLY,
        .loadable_request = N00B_TEST_ELF_LOADABLE_IN_PLACE,
        .loadable_outcome = N00B_ELF_REWRITE_PLAN_ACCEPTED,
        .loadable_reason = N00B_ELF_REWRITE_REJECT_NONE,
        .loadable_admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
        .loadable_phtab_strategy =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE,
        .loadable_phtab_adjust_status =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_RELOCATABLE,
        .loadable_phtab_adjust_reason =
            N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_NONZERO_SLACK,
        .loadable_relocation_status =
            N00B_ELF_REWRITE_LOADABLE_RELOCATION_ACCEPTED,
        .loadable_relocation_reason = N00B_ELF_REWRITE_REJECT_NONE,
        .description   = "Nonzero slack blocks in-place growth; relocation is safe.",
    },
    {
        .name          = "phtab_adjust_at_eof",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_PHTAB_ADJUST_AT_EOF,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "phtab-adjust-at-eof",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_PHTAB_ADJUSTMENT,
        .oracle_expect = N00B_TEST_ELF_ORACLE_PHTAB_NOT_ADJUSTABLE,
        .has_oracle_code = true,
        .oracle_expected_code = N00B_TEST_ELF_ORACLE_CODE_PHTAB_ADJUST_EOF,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_DIAGNOSTIC_ONLY,
        .loadable_request = N00B_TEST_ELF_LOADABLE_IN_PLACE,
        .loadable_outcome = N00B_ELF_REWRITE_PLAN_REJECTED,
        .loadable_reason = N00B_ELF_REWRITE_REJECT_ADMISSION,
        .loadable_admission_reason =
            N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_AT_EOF,
        .loadable_phtab_strategy =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST,
        .loadable_phtab_adjust_status =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_HARD,
        .loadable_phtab_adjust_reason =
            N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_AT_EOF,
        .description   = "Containing load file range already ends at EOF.",
    },
    {
        .name          = "loadable_relocate_direct",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_LOADABLE_RELOCATE_DIRECT,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "loadable-relocate-direct",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_NONE,
        .oracle_expect = N00B_TEST_ELF_ORACLE_VALID_TARGET,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_DIAGNOSTIC_ONLY,
        .loadable_request = N00B_TEST_ELF_LOADABLE_RELOCATE,
        .loadable_outcome = N00B_ELF_REWRITE_PLAN_ACCEPTED,
        .loadable_reason = N00B_ELF_REWRITE_REJECT_NONE,
        .loadable_admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
        .loadable_phtab_strategy =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE,
        .loadable_relocation_status =
            N00B_ELF_REWRITE_LOADABLE_RELOCATION_ACCEPTED,
        .loadable_relocation_reason = N00B_ELF_REWRITE_REJECT_NONE,
        .loadable_apply_reparse = true,
        .description   = "Direct relocated-PHTAB planning succeeds.",
    },
    {
        .name          = "loadable_relocate_overlay_rejected",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_LOADABLE_RELOCATE_OVERLAY,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "loadable-relocate-overlay-rejected",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_NONE,
        .oracle_expect = N00B_TEST_ELF_ORACLE_VALID_TARGET,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_DIAGNOSTIC_ONLY,
        .loadable_request = N00B_TEST_ELF_LOADABLE_RELOCATE,
        .loadable_outcome = N00B_ELF_REWRITE_PLAN_REJECTED,
        .loadable_reason = N00B_ELF_REWRITE_REJECT_LOADABLE_PLACEMENT,
        .loadable_admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
        .loadable_phtab_strategy =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE,
        .loadable_relocation_status =
            N00B_ELF_REWRITE_LOADABLE_RELOCATION_REJECTED,
        .loadable_relocation_reason =
            N00B_ELF_REWRITE_REJECT_LOADABLE_PLACEMENT,
        .description   = "Relocated-PHTAB planning rejects preserved overlay.",
    },
    {
        .name          = "loadable_relocate_address_overflow",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_LOADABLE_RELOCATE_ADDRESS_OVERFLOW,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "loadable-relocate-address-overflow",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_NONE,
        .oracle_expect = N00B_TEST_ELF_ORACLE_VALID_TARGET,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_DIAGNOSTIC_ONLY,
        .loadable_request = N00B_TEST_ELF_LOADABLE_RELOCATE,
        .loadable_outcome = N00B_ELF_REWRITE_PLAN_REJECTED,
        .loadable_reason = N00B_ELF_REWRITE_REJECT_LOADABLE_ADDRESS,
        .loadable_admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
        .loadable_phtab_strategy =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE,
        .loadable_relocation_status =
            N00B_ELF_REWRITE_LOADABLE_RELOCATION_REJECTED,
        .loadable_relocation_reason =
            N00B_ELF_REWRITE_REJECT_LOADABLE_ADDRESS,
        .description   = "After-highest-load address placement overflows.",
    },
    {
        .name          = "valid_minimal_exec",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_VALID_MINIMAL_EXEC,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "ok",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_READ_TARGET,
        .oracle_expect = N00B_TEST_ELF_ORACLE_VALID_TARGET,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_SHARED_SCOPE,
        .admission_request = N00B_TEST_ELF_ADMISSION_RELAXED_EOF,
        .admission_outcome = N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED,
        .admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
        .admission_placement = N00B_ELF_REWRITE_ADMIT_PLACEMENT_EOF_TAIL,
        .rewrite_request = N00B_TEST_ELF_REWRITE_RELAXED_EOF,
        .rewrite_outcome = N00B_ELF_REWRITE_PLAN_ACCEPTED,
        .rewrite_reason = N00B_ELF_REWRITE_REJECT_NONE,
        .rewrite_admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
        .rewrite_admission_placement = N00B_ELF_REWRITE_ADMIT_PLACEMENT_EOF_TAIL,
        .rewrite_table_strategy = N00B_ELF_REWRITE_TABLE_STRATEGY_EOF_REPLACEMENT,
        .loadable_request = N00B_TEST_ELF_LOADABLE_DEFERRED,
        .loadable_outcome = N00B_ELF_REWRITE_PLAN_REJECTED,
        .loadable_reason = N00B_ELF_REWRITE_REJECT_ADMISSION,
        .loadable_admission_reason =
            N00B_ELF_REWRITE_ADMIT_REJECT_PT_PHDR_MISSING,
        .loadable_phtab_strategy = N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_DEFERRED,
        .description   = "Minimal ELF64 executable satisfying Brandon's reader.",
    },
    {
        .name          = "bad_magic",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_BAD_MAGIC,
        .expect_parse  = N00B_TEST_ELF_PARSE_REJECT,
        .expect_reason = "bad_magic",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_READ_TARGET,
        .oracle_expect = N00B_TEST_ELF_ORACLE_INVALID_TARGET,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_SHARED_SCOPE,
        .description   = "Header-sized input without ELF magic.",
    },
    {
        .name          = "elf32_input",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_ELF32_INPUT,
        .expect_parse  = N00B_TEST_ELF_PARSE_REJECT,
        .expect_reason = "unsupported_elf_class",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_READ_TARGET,
        .oracle_expect = N00B_TEST_ELF_ORACLE_INVALID_TARGET,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_SHARED_SCOPE,
        .description   = "ELF magic with EI_CLASS set to ELFCLASS32.",
    },
    {
        .name          = "truncated_header",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_TRUNCATED_HEADER,
        .expect_parse  = N00B_TEST_ELF_PARSE_REJECT,
        .expect_reason = "truncated_header",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_READ_TARGET,
        .oracle_expect = N00B_TEST_ELF_ORACLE_INVALID_TARGET,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_SHARED_SCOPE,
        .description   = "ELF magic but shorter than an ELF64 header.",
    },
    {
        .name          = "phtab_not_in_load",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_PHTAB_NOT_IN_LOAD,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "phtab-outside-load",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_READ_TARGET,
        .oracle_expect = N00B_TEST_ELF_ORACLE_INVALID_TARGET,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_N00B_BROADER,
        .admission_request = N00B_TEST_ELF_ADMISSION_STRICT_EOF,
        .admission_outcome = N00B_ELF_REWRITE_ADMIT_OUTCOME_REJECTED,
        .admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_OUTSIDE_LOAD,
        .admission_placement = N00B_ELF_REWRITE_ADMIT_PLACEMENT_NONE,
        .description   = "PHTAB is present but outside all PT_LOAD ranges.",
    },
    {
        .name          = "entry_outside_load",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_ENTRY_OUTSIDE_LOAD,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "entry-outside-load",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_READ_TARGET,
        .oracle_expect = N00B_TEST_ELF_ORACLE_INVALID_TARGET,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_N00B_BROADER,
        .admission_request = N00B_TEST_ELF_ADMISSION_STRICT_EOF,
        .admission_outcome = N00B_ELF_REWRITE_ADMIT_OUTCOME_REJECTED,
        .admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_ENTRY_OUTSIDE_LOAD,
        .admission_placement = N00B_ELF_REWRITE_ADMIT_PLACEMENT_NONE,
        .description   = "Entrypoint address is outside all PT_LOAD ranges.",
    },
    {
        .name          = "entry_in_mem_not_file",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_ENTRY_IN_MEM_NOT_FILE,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "entry-memory-only",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_READ_TARGET,
        .oracle_expect = N00B_TEST_ELF_ORACLE_INVALID_TARGET,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_N00B_BROADER,
        .admission_request = N00B_TEST_ELF_ADMISSION_STRICT_EOF,
        .admission_outcome = N00B_ELF_REWRITE_ADMIT_OUTCOME_REJECTED,
        .admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_ENTRY_MEMORY_ONLY,
        .admission_placement = N00B_ELF_REWRITE_ADMIT_PLACEMENT_NONE,
        .description   = "Entrypoint is inside p_memsz but outside file bytes.",
    },
    {
        .name          = "pt_phdr_bad_size",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_PT_PHDR_BAD_SIZE,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "pt-phdr-inconsistent",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_READ_TARGET,
        .oracle_expect = N00B_TEST_ELF_ORACLE_INVALID_TARGET,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_N00B_BROADER,
        .admission_request = N00B_TEST_ELF_ADMISSION_STRICT_EOF,
        .admission_outcome = N00B_ELF_REWRITE_ADMIT_OUTCOME_REJECTED,
        .admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_PT_PHDR_INCONSISTENT,
        .admission_placement = N00B_ELF_REWRITE_ADMIT_PLACEMENT_NONE,
        .loadable_request = N00B_TEST_ELF_LOADABLE_IN_PLACE,
        .loadable_outcome = N00B_ELF_REWRITE_PLAN_REJECTED,
        .loadable_reason = N00B_ELF_REWRITE_REJECT_ADMISSION,
        .loadable_admission_reason =
            N00B_ELF_REWRITE_ADMIT_REJECT_PT_PHDR_INCONSISTENT,
        .loadable_phtab_strategy =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST,
        .loadable_phtab_adjust_status =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_HARD,
        .loadable_phtab_adjust_reason =
            N00B_ELF_REWRITE_ADMIT_REJECT_PT_PHDR_INCONSISTENT,
        .description   = "PT_PHDR exists but does not match PHTAB size.",
    },
    {
        .name          = "shstrtab_not_terminated",
        .state         = N00B_TEST_ELF_CASE_EXPLORE,
        .generator     = N00B_TEST_ELF_GEN_SHSTRTAB_NOT_TERMINATED,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "ok",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_READ_TARGET,
        .oracle_expect = N00B_TEST_ELF_ORACLE_VALID_TARGET,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_DIAGNOSTIC_ONLY,
        .description   = "Section string table lacks an in-file trailing NUL.",
    },
    {
        .name          = "overlay_after_segments",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_OVERLAY_AFTER_SEGMENTS,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "overlay-policy",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_NONE,
        .oracle_expect = N00B_TEST_ELF_ORACLE_VALID_TARGET,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_DIAGNOSTIC_ONLY,
        .admission_request = N00B_TEST_ELF_ADMISSION_RELAXED_OVERLAY_PRESERVE,
        .admission_outcome = N00B_ELF_REWRITE_ADMIT_OUTCOME_REJECTED,
        .admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_OVERLAY_POLICY,
        .admission_placement = N00B_ELF_REWRITE_ADMIT_PLACEMENT_NONE,
        .rewrite_request = N00B_TEST_ELF_REWRITE_RELAXED_OVERLAY_PRESERVE,
        .rewrite_outcome = N00B_ELF_REWRITE_PLAN_REJECTED,
        .rewrite_reason = N00B_ELF_REWRITE_REJECT_ADMISSION,
        .rewrite_admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_OVERLAY_POLICY,
        .rewrite_admission_placement = N00B_ELF_REWRITE_ADMIT_PLACEMENT_NONE,
        .rewrite_table_strategy = N00B_ELF_REWRITE_TABLE_STRATEGY_NONE,
        .description   = "Extra bytes appear after all modeled ELF ranges.",
    },
    {
        .name          = "overlay_after_segments_append",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_OVERLAY_AFTER_SEGMENTS,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "overlay-append",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_NONE,
        .oracle_expect = N00B_TEST_ELF_ORACLE_VALID_TARGET,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_DIAGNOSTIC_ONLY,
        .admission_request = N00B_TEST_ELF_ADMISSION_RELAXED_OVERLAY_APPEND,
        .admission_outcome = N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED,
        .admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
        .admission_placement = N00B_ELF_REWRITE_ADMIT_PLACEMENT_AFTER_OVERLAY,
        .rewrite_request = N00B_TEST_ELF_REWRITE_RELAXED_OVERLAY_APPEND,
        .rewrite_outcome = N00B_ELF_REWRITE_PLAN_ACCEPTED,
        .rewrite_reason = N00B_ELF_REWRITE_REJECT_NONE,
        .rewrite_admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
        .rewrite_admission_placement = N00B_ELF_REWRITE_ADMIT_PLACEMENT_AFTER_OVERLAY,
        .rewrite_table_strategy = N00B_ELF_REWRITE_TABLE_STRATEGY_AFTER_OVERLAY_REPLACEMENT,
        .description   = "Overlay-preserving append is accepted only with append policy.",
    },
    {
        .name          = "layout_classification",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_LAYOUT_CLASSIFICATION,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "file-gap-placement",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_NONE,
        .oracle_expect = N00B_TEST_ELF_ORACLE_VALID_TARGET,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_DIAGNOSTIC_ONLY,
        .admission_request = N00B_TEST_ELF_ADMISSION_RELAXED_PREFERRED_GAP,
        .admission_outcome = N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED,
        .admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
        .admission_placement = N00B_ELF_REWRITE_ADMIT_PLACEMENT_FILE_GAP,
        .rewrite_request = N00B_TEST_ELF_REWRITE_RELAXED_PREFERRED_GAP,
        .rewrite_outcome = N00B_ELF_REWRITE_PLAN_ACCEPTED,
        .rewrite_reason = N00B_ELF_REWRITE_REJECT_NONE,
        .rewrite_admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
        .rewrite_admission_placement = N00B_ELF_REWRITE_ADMIT_PLACEMENT_FILE_GAP,
        .rewrite_table_strategy = N00B_ELF_REWRITE_TABLE_STRATEGY_EOF_REPLACEMENT,
        .description   = "ELF with string tables, interpreter, note, and NOBITS.",
    },
    {
        .name          = "layout_nonzero_unknown",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_LAYOUT_NONZERO_UNKNOWN,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "unknown-nonzero-bytes",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_NONE,
        .oracle_expect = N00B_TEST_ELF_ORACLE_VALID_TARGET,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_DIAGNOSTIC_ONLY,
        .admission_request = N00B_TEST_ELF_ADMISSION_RELAXED_PREFERRED_GAP,
        .admission_outcome = N00B_ELF_REWRITE_ADMIT_OUTCOME_REJECTED,
        .admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_UNKNOWN_NONZERO_BYTES,
        .admission_placement = N00B_ELF_REWRITE_ADMIT_PLACEMENT_NONE,
        .description   = "Layout fixture with a nonzero unmodeled byte gap.",
    },
    {
        .name          = "reserved_requested_metadata_name",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_VALID_MINIMAL_EXEC,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "reserved-requested-name",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_NONE,
        .oracle_expect = N00B_TEST_ELF_ORACLE_VALID_TARGET,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_DIAGNOSTIC_ONLY,
        .rewrite_request = N00B_TEST_ELF_REWRITE_RESERVED_REQUESTED_NAME,
        .rewrite_outcome = N00B_ELF_REWRITE_PLAN_REJECTED,
        .rewrite_reason = N00B_ELF_REWRITE_REJECT_ADMISSION,
        .rewrite_admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_RESERVED_SECTION_NAME,
        .rewrite_admission_placement = N00B_ELF_REWRITE_ADMIT_PLACEMENT_NONE,
        .rewrite_table_strategy = N00B_ELF_REWRITE_TABLE_STRATEGY_NONE,
        .description   = "Reserved metadata section names are rejected.",
    },
    {
        .name          = "existing_reserved_metadata_section",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_VALID_MINIMAL_EXEC,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "existing-reserved-section",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_NONE,
        .oracle_expect = N00B_TEST_ELF_ORACLE_VALID_TARGET,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_DIAGNOSTIC_ONLY,
        .target_mutation = N00B_TEST_ELF_TARGET_MUTATION_EXISTING_RESERVED_SECTION_NAME,
        .rewrite_request = N00B_TEST_ELF_REWRITE_RELAXED_EOF,
        .rewrite_outcome = N00B_ELF_REWRITE_PLAN_REJECTED,
        .rewrite_reason = N00B_ELF_REWRITE_REJECT_ADMISSION,
        .rewrite_admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_RESERVED_SECTION_NAME,
        .rewrite_admission_placement = N00B_ELF_REWRITE_ADMIT_PLACEMENT_NONE,
        .rewrite_table_strategy = N00B_ELF_REWRITE_TABLE_STRATEGY_NONE,
        .description   = "Targets that already carry reserved metadata sections are rejected.",
    },
    {
        .name          = "loadable_phnum_xnum",
        .state         = N00B_TEST_ELF_CASE_KNOWN,
        .generator     = N00B_TEST_ELF_GEN_VALID_MINIMAL_EXEC,
        .expect_parse  = N00B_TEST_ELF_PARSE_OK,
        .expect_reason = "loadable-phnum-xnum",
        .oracle_mode   = N00B_TEST_ELF_ORACLE_NONE,
        .oracle_expect = N00B_TEST_ELF_ORACLE_VALID_TARGET,
        .divergence    = N00B_TEST_ELF_DIVERGENCE_DIAGNOSTIC_ONLY,
        .target_mutation = N00B_TEST_ELF_TARGET_MUTATION_PHNUM_XNUM,
        .has_target_profile = true,
        .target_profile_reason = N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_PXNUM,
        .target_profile_packager_errcode = 21,
        .loadable_request = N00B_TEST_ELF_LOADABLE_DEFERRED,
        .loadable_outcome = N00B_ELF_REWRITE_PLAN_REJECTED,
        .loadable_reason = N00B_ELF_REWRITE_REJECT_TARGET_PROFILE,
        .loadable_admission_reason = N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
        .loadable_phtab_strategy =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_NONE,
        .description   = "Loadable insertion rejects PN_XNUM target profile.",
    },
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_invalid_ehsize",
        "invalid-ehsize",
        N00B_TEST_ELF_TARGET_MUTATION_INVALID_EHSIZE,
        N00B_ELF_REWRITE_PROFILE_INVALID_EHSIZE,
        11,
        "Packager parity: e_ehsize must match Elf64_Ehdr."),
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_invalid_shentsize",
        "invalid-shentsize",
        N00B_TEST_ELF_TARGET_MUTATION_INVALID_SHENTSIZE,
        N00B_ELF_REWRITE_PROFILE_INVALID_SHENTSIZE,
        15,
        "Packager parity: section-header entry size."),
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_invalid_phentsize",
        "invalid-phentsize",
        N00B_TEST_ELF_TARGET_MUTATION_INVALID_PHENTSIZE,
        N00B_ELF_REWRITE_PROFILE_INVALID_PHENTSIZE,
        16,
        "Packager parity: program-header entry size."),
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_shnum_zero",
        "shnum-zero",
        N00B_TEST_ELF_TARGET_MUTATION_SHNUM_ZERO,
        N00B_ELF_REWRITE_PROFILE_SHTAB_SIZE,
        18,
        "Packager parity: e_shnum zero rejects."),
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_shnum_one",
        "shnum-one",
        N00B_TEST_ELF_TARGET_MUTATION_SHNUM_ONE,
        N00B_ELF_REWRITE_PROFILE_SHTAB_SIZE,
        18,
        "Packager parity: e_shnum one rejects."),
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_shnum_loreserve",
        "shnum-loreserve",
        N00B_TEST_ELF_TARGET_MUTATION_SHNUM_LORESERVE,
        N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_SHNLO,
        17,
        "Packager parity: e_shnum at SHN_LORESERVE rejects."),
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_shnum_xindex",
        "shnum-xindex",
        N00B_TEST_ELF_TARGET_MUTATION_SHNUM_XINDEX,
        N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_SHNLO,
        17,
        "Packager parity: SHN_XINDEX section-count form rejects."),
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_shoff_zero",
        "shoff-zero",
        N00B_TEST_ELF_TARGET_MUTATION_SHOFF_ZERO,
        N00B_ELF_REWRITE_PROFILE_SHTAB_SIZE,
        18,
        "Packager parity: zero section-header offset rejects."),
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_shoff_out_of_bounds",
        "shoff-out-of-bounds",
        N00B_TEST_ELF_TARGET_MUTATION_SHOFF_OUT_OF_BOUNDS,
        N00B_ELF_REWRITE_PROFILE_INVALID_SHTAB_BOUNDS,
        19,
        "Packager parity: SHTAB outside file rejects."),
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_shoff_wrap",
        "shoff-wrap",
        N00B_TEST_ELF_TARGET_MUTATION_SHOFF_WRAP,
        N00B_ELF_REWRITE_PROFILE_INVALID_SHTAB_BOUNDS,
        19,
        "Packager parity: SHTAB offset overflow rejects."),
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_shstrndx_zero",
        "shstrndx-zero",
        N00B_TEST_ELF_TARGET_MUTATION_SHSTRNDX_ZERO,
        N00B_ELF_REWRITE_PROFILE_NO_STRTAB,
        24,
        "Packager parity: no section-name string table rejects."),
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_shstrndx_loreserve",
        "shstrndx-loreserve",
        N00B_TEST_ELF_TARGET_MUTATION_SHSTRNDX_LORESERVE,
        N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_STRTAB_SHNLO,
        26,
        "Packager parity: e_shstrndx at SHN_LORESERVE rejects."),
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_shstrndx_xindex",
        "shstrndx-xindex",
        N00B_TEST_ELF_TARGET_MUTATION_SHSTRNDX_XINDEX,
        N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_STRTAB_SHNLO,
        26,
        "Packager parity: SHN_XINDEX section-name table form rejects."),
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_shstrndx_out_of_range",
        "shstrndx-out-of-range",
        N00B_TEST_ELF_TARGET_MUTATION_SHSTRNDX_OUT_OF_RANGE,
        N00B_ELF_REWRITE_PROFILE_INVALID_STRTAB_INDEX,
        27,
        "Packager parity: e_shstrndx beyond section count rejects."),
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_shstrtab_wrong_type",
        "shstrtab-wrong-type",
        N00B_TEST_ELF_TARGET_MUTATION_SHSTRTAB_WRONG_TYPE,
        N00B_ELF_REWRITE_PROFILE_INVALID_STRTAB_TYPE,
        28,
        "Packager parity: .shstrtab must be SHT_STRTAB."),
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_shstrtab_invalid_size",
        "shstrtab-size",
        N00B_TEST_ELF_TARGET_MUTATION_SHSTRTAB_INVALID_SIZE,
        N00B_ELF_REWRITE_PROFILE_STRTAB_SIZE,
        29,
        "Packager parity: .shstrtab bounds reject."),
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_shstrtab_offset_wrap",
        "shstrtab-offset-wrap",
        N00B_TEST_ELF_TARGET_MUTATION_SHSTRTAB_OFFSET_WRAP,
        N00B_ELF_REWRITE_PROFILE_STRTAB_SIZE,
        29,
        "Packager parity: .shstrtab offset overflow rejects."),
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_section_name_index",
        "section-name-index",
        N00B_TEST_ELF_TARGET_MUTATION_SECTION_NAME_INDEX,
        N00B_ELF_REWRITE_PROFILE_SECTION_NAME_INDEX,
        35,
        "Packager parity: section names must fit in reported strtab size."),
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_phnum_zero",
        "phnum-zero",
        N00B_TEST_ELF_TARGET_MUTATION_PHNUM_ZERO,
        N00B_ELF_REWRITE_PROFILE_ZERO_PHNUM,
        20,
        "Packager parity: e_phnum zero rejects."),
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_phnum_xnum",
        "phnum-xnum",
        N00B_TEST_ELF_TARGET_MUTATION_PHNUM_XNUM,
        N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_PXNUM,
        21,
        "Packager parity: PN_XNUM program-header form rejects."),
    N00B_TEST_ELF_PROFILE_CASE(
        "profile_phoff_wrap",
        "phoff-wrap",
        N00B_TEST_ELF_TARGET_MUTATION_PHOFF_WRAP,
        N00B_ELF_REWRITE_PROFILE_INVALID_PHTAB_BOUNDS,
        23,
        "Packager parity: PHTAB offset overflow rejects."),
};

#undef N00B_TEST_ELF_PROFILE_CASE

static const size_t n00b_test_elf_case_count =
    sizeof(n00b_test_elf_cases) / sizeof(n00b_test_elf_cases[0]);

static inline const char *
n00b_test_elf_case_state_name(n00b_test_elf_case_state_t state)
{
    switch (state) {
    case N00B_TEST_ELF_CASE_KNOWN:
        return "known";
    case N00B_TEST_ELF_CASE_EXPLORE:
        return "explore";
    case N00B_TEST_ELF_CASE_PENDING:
        return "pending";
    case N00B_TEST_ELF_CASE_DIVERGE:
        return "diverge";
    case N00B_TEST_ELF_CASE_RETIRED:
        return "retired";
    }

    return "unknown";
}

static inline const char *
n00b_test_elf_oracle_mode_arg(n00b_test_elf_oracle_mode_t mode)
{
    switch (mode) {
    case N00B_TEST_ELF_ORACLE_NONE:
        return "none";
    case N00B_TEST_ELF_ORACLE_READ_TARGET:
        return "read-target";
    case N00B_TEST_ELF_ORACLE_PHTAB_ADJUSTMENT:
        return "phtab-adjustment";
    }

    return "none";
}

static inline const char *
n00b_test_elf_oracle_expect_name(n00b_test_elf_oracle_expect_t expect)
{
    switch (expect) {
    case N00B_TEST_ELF_ORACLE_VALID_TARGET:
        return "valid-target";
    case N00B_TEST_ELF_ORACLE_INVALID_TARGET:
        return "invalid-target";
    case N00B_TEST_ELF_ORACLE_PHTAB_ADJUSTABLE:
        return "phtab-adjustable";
    case N00B_TEST_ELF_ORACLE_PHTAB_NOT_ADJUSTABLE:
        return "phtab-not-adjustable";
    }

    return "oracle-error";
}

static inline const char *
n00b_test_elf_divergence_name(n00b_test_elf_divergence_t divergence)
{
    switch (divergence) {
    case N00B_TEST_ELF_DIVERGENCE_SHARED_SCOPE:
        return "shared-scope";
    case N00B_TEST_ELF_DIVERGENCE_N00B_BROADER:
        return "n00b-broader";
    case N00B_TEST_ELF_DIVERGENCE_BRANDON_NARROWER:
        return "brandon-narrower";
    case N00B_TEST_ELF_DIVERGENCE_DIAGNOSTIC_ONLY:
        return "diagnostic-only";
    }

    return "diagnostic-only";
}

static inline bool
n00b_test_elf_case_has_admission(const n00b_test_elf_case_t *test_case)
{
    return test_case->admission_request != N00B_TEST_ELF_ADMISSION_NONE;
}

static inline bool
n00b_test_elf_case_has_target_profile(const n00b_test_elf_case_t *test_case)
{
    return test_case->has_target_profile;
}

static inline bool
n00b_test_elf_case_has_rewrite(const n00b_test_elf_case_t *test_case)
{
    return test_case->rewrite_request != N00B_TEST_ELF_REWRITE_NONE;
}

static inline bool
n00b_test_elf_case_has_loadable(const n00b_test_elf_case_t *test_case)
{
    return test_case->loadable_request != N00B_TEST_ELF_LOADABLE_NONE;
}

static inline bool
n00b_test_elf_case_has_oracle_code(const n00b_test_elf_case_t *test_case)
{
    return test_case->has_oracle_code;
}

static inline const n00b_test_elf_case_t *
n00b_test_elf_case_by_name(const char *name)
{
    for (size_t i = 0; i < n00b_test_elf_case_count; i++) {
        if (strcmp(n00b_test_elf_cases[i].name, name) == 0) {
            return &n00b_test_elf_cases[i];
        }
    }

    return nullptr;
}

static inline const char *
n00b_test_elf_rewrite_request_name(n00b_test_elf_rewrite_request_t request)
{
    switch (request) {
    case N00B_TEST_ELF_REWRITE_NONE:
        return "none";
    case N00B_TEST_ELF_REWRITE_RELAXED_EOF:
        return "relaxed-eof";
    case N00B_TEST_ELF_REWRITE_RELAXED_PREFERRED_GAP:
        return "relaxed-preferred-gap";
    case N00B_TEST_ELF_REWRITE_RELAXED_OVERLAY_PRESERVE:
        return "relaxed-overlay-preserve";
    case N00B_TEST_ELF_REWRITE_RELAXED_OVERLAY_APPEND:
        return "relaxed-overlay-append";
    case N00B_TEST_ELF_REWRITE_RESERVED_REQUESTED_NAME:
        return "reserved-requested-name";
    }

    return "none";
}

static void
n00b_test_elf_put16(uint8_t *p, uint16_t v)
{
    memcpy(p, &v, sizeof(v));
}

static void
n00b_test_elf_put32(uint8_t *p, uint32_t v)
{
    memcpy(p, &v, sizeof(v));
}

static void
n00b_test_elf_put64(uint8_t *p, uint64_t v)
{
    memcpy(p, &v, sizeof(v));
}

static n00b_buffer_t *
n00b_test_elf_new_zeroed(size_t size)
{
    n00b_buffer_t *buf = n00b_buffer_new((int64_t)size);
    for (size_t i = 0; i < size; i++) {
        buf->data[i] = 0;
    }
    buf->byte_len = size;
    return buf;
}

static void
n00b_test_elf_write_header(uint8_t *p,
                           uint16_t type,
                           uint64_t entry,
                           uint64_t phoff,
                           uint16_t phnum,
                           uint64_t shoff,
                           uint16_t shnum,
                           uint16_t shstrndx)
{
    p[0] = 0x7f;
    p[1] = 'E';
    p[2] = 'L';
    p[3] = 'F';
    p[EI_CLASS]   = ELFCLASS64;
    p[EI_DATA]    = ELFDATA2LSB;
    p[EI_VERSION] = EV_CURRENT;

    n00b_test_elf_put16(p + 16, type);
    n00b_test_elf_put16(p + 18, EM_X86_64);
    n00b_test_elf_put32(p + 20, EV_CURRENT);
    n00b_test_elf_put64(p + 24, entry);
    n00b_test_elf_put64(p + 32, phoff);
    n00b_test_elf_put64(p + 40, shoff);
    n00b_test_elf_put16(p + 52, 64);
    n00b_test_elf_put16(p + 54, 56);
    n00b_test_elf_put16(p + 56, phnum);
    n00b_test_elf_put16(p + 58, 64);
    n00b_test_elf_put16(p + 60, shnum);
    n00b_test_elf_put16(p + 62, shstrndx);
}

static void
n00b_test_elf_write_phdr(uint8_t *p,
                         uint32_t type,
                         uint32_t flags,
                         uint64_t offset,
                         uint64_t vaddr,
                         uint64_t filesz,
                         uint64_t memsz,
                         uint64_t align)
{
    n00b_test_elf_put32(p + 0, type);
    n00b_test_elf_put32(p + 4, flags);
    n00b_test_elf_put64(p + 8, offset);
    n00b_test_elf_put64(p + 16, vaddr);
    n00b_test_elf_put64(p + 24, vaddr);
    n00b_test_elf_put64(p + 32, filesz);
    n00b_test_elf_put64(p + 40, memsz);
    n00b_test_elf_put64(p + 48, align);
}

static void
n00b_test_elf_write_shdr(uint8_t *p,
                         uint32_t name,
                         uint32_t type,
                         uint64_t flags,
                         uint64_t addr,
                         uint64_t offset,
                         uint64_t size,
                         uint32_t link,
                         uint32_t info,
                         uint64_t addralign,
                         uint64_t entsize)
{
    n00b_test_elf_put32(p + 0, name);
    n00b_test_elf_put32(p + 4, type);
    n00b_test_elf_put64(p + 8, flags);
    n00b_test_elf_put64(p + 16, addr);
    n00b_test_elf_put64(p + 24, offset);
    n00b_test_elf_put64(p + 32, size);
    n00b_test_elf_put32(p + 40, link);
    n00b_test_elf_put32(p + 44, info);
    n00b_test_elf_put64(p + 48, addralign);
    n00b_test_elf_put64(p + 56, entsize);
}

static void
n00b_test_elf_write_shstrtab(uint8_t *p, size_t offset, bool terminated)
{
    uint8_t *strtab = p + offset;
    strtab[0] = '\0';
    memcpy(strtab + 1, ".shstrtab", 9);

    if (terminated) {
        strtab[10] = '\0';
    }
}

static n00b_buffer_t *
n00b_test_elf_minimal_exec(uint64_t entry,
                           uint64_t load_offset,
                           uint64_t load_vaddr,
                           uint64_t load_filesz,
                           uint64_t load_memsz,
                           bool include_pt_phdr,
                           bool bad_pt_phdr,
                           bool shstrtab_terminated,
                           bool include_overlay)
{
    const size_t base_size     = 512;
    const size_t overlay_size  = include_overlay ? 16 : 0;
    const size_t total_size    = base_size + overlay_size;
    const size_t phoff         = 64;
    const size_t phnum         = include_pt_phdr ? 2 : 1;
    const size_t shoff         = 256;
    const size_t shnum         = 2;
    const size_t shstrtab_off  = 384;
    const size_t shstrtab_size = shstrtab_terminated ? 11 : 10;

    n00b_buffer_t *buf = n00b_test_elf_new_zeroed(total_size);
    uint8_t       *p   = (uint8_t *)buf->data;

    n00b_test_elf_write_header(p, ET_EXEC, entry, phoff, (uint16_t)phnum,
                               shoff, (uint16_t)shnum, 1);

    n00b_test_elf_write_phdr(p + phoff,
                             PT_LOAD,
                             PF_R | PF_X,
                             load_offset,
                             load_vaddr,
                             load_filesz,
                             load_memsz,
                             0x1000);

    if (include_pt_phdr) {
        uint64_t phtab_size = phnum * 56;
        uint64_t phdr_size  = bad_pt_phdr ? 56 : phtab_size;

        n00b_test_elf_write_phdr(p + phoff + 56,
                                 PT_PHDR,
                                 PF_R,
                                 phoff,
                                 load_vaddr + phoff - load_offset,
                                 phdr_size,
                                 phdr_size,
                                 8);
    }

    n00b_test_elf_write_shdr(p + shoff + 64,
                             1,
                             SHT_STRTAB,
                             0,
                             0,
                             shstrtab_off,
                             shstrtab_size,
                             0,
                             0,
                             1,
                             0);
    n00b_test_elf_write_shstrtab(p, shstrtab_off, shstrtab_terminated);

    if (include_overlay) {
        for (size_t i = 0; i < overlay_size; i++) {
            p[base_size + i] = (uint8_t)(0xa0 + i);
        }
    }

    return buf;
}

static n00b_buffer_t *
n00b_test_elf_layout_classification(bool nonzero_unknown)
{
    const size_t total_size = 1152;
    const size_t phoff      = 64;
    const size_t phnum      = 3;
    const size_t shoff      = 640;
    const size_t shnum      = 8;

    const size_t interp_off = 240;
    const size_t interp_sz  = 16;
    const size_t note_off   = 256;
    const size_t note_sz    = 32;
    const size_t shstr_off  = 320;
    const size_t shstr_sz   = 54;
    const size_t str_off    = 384;
    const size_t str_sz     = 16;
    const size_t dynstr_off = 416;
    const size_t dynstr_sz  = 16;
    const size_t sym_off    = 448;
    const size_t sym_sz     = 2 * 24;
    const size_t dynsym_off = 512;
    const size_t dynsym_sz  = 2 * 24;

    n00b_buffer_t *buf = n00b_test_elf_new_zeroed(total_size);
    uint8_t       *p   = (uint8_t *)buf->data;

    n00b_test_elf_write_header(p, ET_EXEC, 0x400080, phoff, (uint16_t)phnum,
                               shoff, (uint16_t)shnum, 1);

    n00b_test_elf_write_phdr(p + phoff,
                             PT_LOAD,
                             PF_R | PF_X,
                             0,
                             0x400000,
                             232,
                             232,
                             0x1000);
    n00b_test_elf_write_phdr(p + phoff + 56,
                             PT_INTERP,
                             PF_R,
                             interp_off,
                             0x400000 + interp_off,
                             interp_sz,
                             interp_sz,
                             1);
    n00b_test_elf_write_phdr(p + phoff + 112,
                             PT_NOTE,
                             PF_R,
                             note_off,
                             0x400000 + note_off,
                             note_sz,
                             note_sz,
                             4);

    memcpy(p + interp_off, "/lib/ld.so", 10);
    p[interp_off + 10] = '\0';

    n00b_test_elf_put32(p + note_off + 0, 4);
    n00b_test_elf_put32(p + note_off + 4, 16);
    n00b_test_elf_put32(p + note_off + 8, NT_GNU_ABI_TAG);
    memcpy(p + note_off + 12, "GNU", 3);
    p[note_off + 15] = '\0';

    uint8_t *shstr = p + shstr_off;
    shstr[0] = '\0';
    memcpy(shstr + 1, ".shstrtab", 9);
    shstr[10] = '\0';
    memcpy(shstr + 11, ".strtab", 7);
    shstr[18] = '\0';
    memcpy(shstr + 19, ".symtab", 7);
    shstr[26] = '\0';
    memcpy(shstr + 27, ".dynstr", 7);
    shstr[34] = '\0';
    memcpy(shstr + 35, ".dynsym", 7);
    shstr[42] = '\0';
    memcpy(shstr + 43, ".note", 5);
    shstr[48] = '\0';
    memcpy(shstr + 49, ".bss", 4);
    shstr[53] = '\0';

    uint8_t *str = p + str_off;
    str[0] = '\0';
    memcpy(str + 1, "main", 4);
    str[5] = '\0';

    uint8_t *dynstr = p + dynstr_off;
    dynstr[0] = '\0';
    memcpy(dynstr + 1, "puts", 4);
    dynstr[5] = '\0';

    uint8_t *sym = p + sym_off + 24;
    n00b_test_elf_put32(sym + 0, 1);
    sym[4] = N00B_ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    n00b_test_elf_put16(sym + 6, 1);
    n00b_test_elf_put64(sym + 8, 0x400080);

    uint8_t *dynsym = p + dynsym_off + 24;
    n00b_test_elf_put32(dynsym + 0, 1);
    dynsym[4] = N00B_ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    n00b_test_elf_put16(dynsym + 6, 1);
    n00b_test_elf_put64(dynsym + 8, 0x400090);

    uint8_t *sh = p + shoff;
    n00b_test_elf_write_shdr(sh + 64,
                             1,
                             SHT_STRTAB,
                             0,
                             0,
                             shstr_off,
                             shstr_sz,
                             0,
                             0,
                             1,
                             0);
    n00b_test_elf_write_shdr(sh + 128,
                             11,
                             SHT_STRTAB,
                             0,
                             0,
                             str_off,
                             str_sz,
                             0,
                             0,
                             1,
                             0);
    n00b_test_elf_write_shdr(sh + 192,
                             19,
                             SHT_SYMTAB,
                             0,
                             0,
                             sym_off,
                             sym_sz,
                             2,
                             1,
                             8,
                             24);
    n00b_test_elf_write_shdr(sh + 256,
                             27,
                             SHT_STRTAB,
                             SHF_ALLOC,
                             0x400000 + dynstr_off,
                             dynstr_off,
                             dynstr_sz,
                             0,
                             0,
                             1,
                             0);
    n00b_test_elf_write_shdr(sh + 320,
                             35,
                             SHT_DYNSYM,
                             SHF_ALLOC,
                             0x400000 + dynsym_off,
                             dynsym_off,
                             dynsym_sz,
                             4,
                             1,
                             8,
                             24);
    n00b_test_elf_write_shdr(sh + 384,
                             43,
                             SHT_NOTE,
                             SHF_ALLOC,
                             0x400000 + note_off,
                             note_off,
                             note_sz,
                             0,
                             0,
                             4,
                             0);
    n00b_test_elf_write_shdr(sh + 448,
                             49,
                             SHT_NOBITS,
                             SHF_ALLOC | SHF_WRITE,
                             0x400600,
                             576,
                             32,
                             0,
                             0,
                             16,
                             0);

    if (nonzero_unknown) {
        p[300] = 0xcc;
    }

    return buf;
}

static n00b_buffer_t *
n00b_test_elf_phtab_adjustment(bool memory_collision,
                               bool file_collision,
                               bool nonzero_slack,
                               bool at_eof,
                               bool extra_data_before_eof)
{
    const size_t total_size = extra_data_before_eof ? 800 : 768;
    const size_t phoff      = 64;
    const bool   second_load = memory_collision || file_collision
                            || nonzero_slack;
    const size_t phnum      = second_load ? 3 : 2;
    const size_t load_filesz = at_eof ? 768 : (second_load ? 240 : 200);
    const size_t load_memsz  = load_filesz;
    const size_t shoff      = file_collision ? 320 : 512;
    const size_t shnum      = 2;
    const size_t shstr_off  = 704;
    const size_t shstr_size = 11;

    n00b_buffer_t *buf = n00b_test_elf_new_zeroed(total_size);
    uint8_t       *p   = (uint8_t *)buf->data;

    n00b_test_elf_write_header(p, ET_EXEC, 0x400080, phoff, (uint16_t)phnum,
                               shoff, (uint16_t)shnum, 1);
    n00b_test_elf_write_phdr(p + phoff,
                             PT_LOAD,
                             PF_R | PF_X,
                             0,
                             0x400000,
                             load_filesz,
                             load_memsz,
                             0x1000);
    n00b_test_elf_write_phdr(p + phoff + 56,
                             PT_PHDR,
                             PF_R,
                             phoff,
                             0x400000 + phoff,
                             phnum * 56,
                             phnum * 56,
                             8);

    if (memory_collision) {
        n00b_test_elf_write_phdr(p + phoff + 112,
                                 PT_LOAD,
                                 PF_R,
                                 640,
                                 0x400800,
                                 total_size - 640,
                                 total_size - 640,
                                 0x1000);
    } else if (file_collision) {
        n00b_test_elf_write_phdr(p + phoff + 112,
                                 PT_LOAD,
                                 PF_R,
                                 240,
                                 0x500000,
                                 total_size - 240,
                                 total_size - 240,
                                 0x1000);
    } else if (nonzero_slack) {
        n00b_test_elf_write_phdr(p + phoff + 112,
                                 PT_LOAD,
                                 PF_R,
                                 512,
                                 0x500000,
                                 total_size - 512,
                                 total_size - 512,
                                 0x1000);
    }

    n00b_test_elf_write_shdr(p + shoff + 64,
                             1,
                             SHT_STRTAB,
                             0,
                             0,
                             shstr_off,
                             shstr_size,
                             0,
                             0,
                             1,
                             0);
    n00b_test_elf_write_shstrtab(p, shstr_off, true);

    if (nonzero_slack) {
        p[248] = 0xcc;
    }

    return buf;
}

static n00b_buffer_t *
n00b_test_elf_loadable_relocate_address_overflow(void)
{
    const size_t total_size = 511;
    const size_t phoff      = 64;
    const size_t phnum      = 2;
    const size_t shoff      = 256;
    const size_t shnum      = 2;
    const size_t shstr_off  = 384;
    uint64_t high_vaddr     = UINT64_MAX - (uint64_t)total_size;

    n00b_buffer_t *buf = n00b_test_elf_new_zeroed(total_size);
    uint8_t       *p   = (uint8_t *)buf->data;

    n00b_test_elf_write_header(p, ET_EXEC, 0, phoff, (uint16_t)phnum,
                               shoff, (uint16_t)shnum, 1);
    n00b_test_elf_write_phdr(p + phoff,
                             PT_LOAD,
                             PF_R | PF_X,
                             0,
                             high_vaddr,
                             total_size,
                             total_size,
                             0x1000);
    n00b_test_elf_write_phdr(p + phoff + 56,
                             PT_PHDR,
                             PF_R,
                             phoff,
                             high_vaddr + phoff,
                             phnum * 56,
                             phnum * 56,
                             8);
    n00b_test_elf_write_shdr(p + shoff + 64,
                             1,
                             SHT_STRTAB,
                             0,
                             0,
                             shstr_off,
                             11,
                             0,
                             0,
                             1,
                             0);
    n00b_test_elf_write_shstrtab(p, shstr_off, true);
    return buf;
}

static void
n00b_test_elf_apply_target_mutation(n00b_buffer_t *buf,
                                    n00b_test_elf_target_mutation_t mutation)
{
    uint8_t *p = (uint8_t *)buf->data;

    switch (mutation) {
    case N00B_TEST_ELF_TARGET_MUTATION_NONE:
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_INVALID_EHSIZE:
        n00b_test_elf_put16(p + N00B_TEST_ELF_E_EHSIZE, 65);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_INVALID_SHENTSIZE:
        n00b_test_elf_put16(p + N00B_TEST_ELF_E_SHENTSIZE, 65);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_INVALID_PHENTSIZE:
        n00b_test_elf_put16(p + N00B_TEST_ELF_E_PHENTSIZE, 57);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHNUM_ZERO:
        n00b_test_elf_put16(p + N00B_TEST_ELF_E_SHNUM, 0);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHNUM_ONE:
        n00b_test_elf_put16(p + N00B_TEST_ELF_E_SHNUM, 1);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHNUM_LORESERVE:
        n00b_test_elf_put16(p + N00B_TEST_ELF_E_SHNUM,
                            N00B_TEST_ELF_SHN_LORESERVE);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHNUM_XINDEX:
        n00b_test_elf_put16(p + N00B_TEST_ELF_E_SHNUM, SHN_XINDEX);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHOFF_ZERO:
        n00b_test_elf_put64(p + N00B_TEST_ELF_E_SHOFF, 0);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHOFF_OUT_OF_BOUNDS:
        n00b_test_elf_put64(p + N00B_TEST_ELF_E_SHOFF, buf->byte_len);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHOFF_WRAP:
        n00b_test_elf_put64(p + N00B_TEST_ELF_E_SHOFF, UINT64_MAX - 32);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHSTRNDX_ZERO:
        n00b_test_elf_put16(p + N00B_TEST_ELF_E_SHSTRNDX, 0);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHSTRNDX_LORESERVE:
        n00b_test_elf_put16(p + N00B_TEST_ELF_E_SHSTRNDX,
                            N00B_TEST_ELF_SHN_LORESERVE);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHSTRNDX_XINDEX:
        n00b_test_elf_put16(p + N00B_TEST_ELF_E_SHSTRNDX, SHN_XINDEX);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHSTRNDX_OUT_OF_RANGE:
        n00b_test_elf_put16(p + N00B_TEST_ELF_E_SHSTRNDX, 2);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHSTRTAB_WRONG_TYPE:
        n00b_test_elf_put32(p + N00B_TEST_ELF_SHSTRTAB_SH
                              + N00B_TEST_ELF_SH_TYPE,
                            SHT_PROGBITS);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHSTRTAB_INVALID_SIZE:
        n00b_test_elf_put64(p + N00B_TEST_ELF_SHSTRTAB_SH
                              + N00B_TEST_ELF_SH_SIZE,
                            1024);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHSTRTAB_OFFSET_WRAP:
        n00b_test_elf_put64(p + N00B_TEST_ELF_SHSTRTAB_SH
                              + N00B_TEST_ELF_SH_OFFSET,
                            UINT64_MAX - 4);
        n00b_test_elf_put64(p + N00B_TEST_ELF_SHSTRTAB_SH
                              + N00B_TEST_ELF_SH_SIZE,
                            16);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SECTION_NAME_INDEX:
        n00b_test_elf_put32(p + N00B_TEST_ELF_SHSTRTAB_SH
                              + N00B_TEST_ELF_SH_NAME,
                            11);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_PHNUM_ZERO:
        n00b_test_elf_put16(p + N00B_TEST_ELF_E_PHNUM, 0);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_PHNUM_XNUM:
        n00b_test_elf_put16(p + N00B_TEST_ELF_E_PHNUM, N00B_TEST_ELF_PN_XNUM);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_PHOFF_WRAP:
        n00b_test_elf_put64(p + N00B_TEST_ELF_E_PHOFF, UINT64_MAX - 16);
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_EXISTING_RESERVED_SECTION_NAME:
        memcpy(p + 384 + 11, ".chalk.mark", sizeof(".chalk.mark"));
        n00b_test_elf_put32(p + N00B_TEST_ELF_SHSTRTAB_SH
                              + N00B_TEST_ELF_SH_NAME,
                            11);
        n00b_test_elf_put64(p + N00B_TEST_ELF_SHSTRTAB_SH
                              + N00B_TEST_ELF_SH_SIZE,
                            23);
        break;
    }
}

static n00b_buffer_t *
n00b_test_elf_case_generate(const n00b_test_elf_case_t *test_case)
{
    n00b_buffer_t *buf = nullptr;

    switch (test_case->generator) {
    case N00B_TEST_ELF_GEN_VALID_MINIMAL_EXEC:
        buf = n00b_test_elf_minimal_exec(0x400080, 0, 0x400000, 512, 512,
                                         false, false, true, false);
        break;
    case N00B_TEST_ELF_GEN_BAD_MAGIC: {
        buf = n00b_test_elf_new_zeroed(64);
        memcpy(buf->data, "NOPE", 4);
        break;
    }
    case N00B_TEST_ELF_GEN_ELF32_INPUT: {
        buf = n00b_test_elf_new_zeroed(64);
        uint8_t *p = (uint8_t *)buf->data;
        p[0] = 0x7f;
        p[1] = 'E';
        p[2] = 'L';
        p[3] = 'F';
        p[EI_CLASS]   = ELFCLASS32;
        p[EI_DATA]    = ELFDATA2LSB;
        p[EI_VERSION] = EV_CURRENT;
        break;
    }
    case N00B_TEST_ELF_GEN_TRUNCATED_HEADER: {
        buf = n00b_test_elf_new_zeroed(16);
        uint8_t *p = (uint8_t *)buf->data;
        p[0] = 0x7f;
        p[1] = 'E';
        p[2] = 'L';
        p[3] = 'F';
        p[EI_CLASS]   = ELFCLASS64;
        p[EI_DATA]    = ELFDATA2LSB;
        p[EI_VERSION] = EV_CURRENT;
        break;
    }
    case N00B_TEST_ELF_GEN_PHTAB_NOT_IN_LOAD:
        buf = n00b_test_elf_minimal_exec(0x400000, 128, 0x400000, 384, 384,
                                         false, false, true, false);
        break;
    case N00B_TEST_ELF_GEN_ENTRY_OUTSIDE_LOAD:
        buf = n00b_test_elf_minimal_exec(0x500000, 0, 0x400000, 512, 512,
                                         true, false, true, false);
        break;
    case N00B_TEST_ELF_GEN_ENTRY_IN_MEM_NOT_FILE:
        buf = n00b_test_elf_minimal_exec(0x400101, 0, 0x400000, 0x100, 0x2000,
                                         true, false, true, false);
        break;
    case N00B_TEST_ELF_GEN_PT_PHDR_BAD_SIZE:
        buf = n00b_test_elf_minimal_exec(0x400080, 0, 0x400000, 512, 512,
                                         true, true, true, false);
        break;
    case N00B_TEST_ELF_GEN_SHSTRTAB_NOT_TERMINATED:
        buf = n00b_test_elf_minimal_exec(0x400080, 0, 0x400000, 512, 512,
                                         false, false, false, false);
        break;
    case N00B_TEST_ELF_GEN_OVERLAY_AFTER_SEGMENTS:
        buf = n00b_test_elf_minimal_exec(0x400080, 0, 0x400000, 512, 512,
                                         false, false, true, true);
        break;
    case N00B_TEST_ELF_GEN_LAYOUT_CLASSIFICATION:
        buf = n00b_test_elf_layout_classification(false);
        break;
    case N00B_TEST_ELF_GEN_LAYOUT_NONZERO_UNKNOWN:
        buf = n00b_test_elf_layout_classification(true);
        break;
    case N00B_TEST_ELF_GEN_PHTAB_ADJUST_ACCEPTED:
        buf = n00b_test_elf_phtab_adjustment(false, false, false, false, false);
        break;
    case N00B_TEST_ELF_GEN_PHTAB_ADJUST_MEMORY_TAIL:
        buf = n00b_test_elf_phtab_adjustment(false, false, false, false, false);
        n00b_test_elf_put64((uint8_t *)buf->data
                                + 64
                                + N00B_TEST_ELF_PHDR_P_MEMSZ,
                            256);
        break;
    case N00B_TEST_ELF_GEN_PHTAB_ADJUST_MEMORY_COLLISION:
        buf = n00b_test_elf_phtab_adjustment(true, false, false, false, false);
        break;
    case N00B_TEST_ELF_GEN_PHTAB_ADJUST_FILE_COLLISION:
        buf = n00b_test_elf_phtab_adjustment(false, true, false, false, false);
        break;
    case N00B_TEST_ELF_GEN_PHTAB_ADJUST_NONZERO_SLACK:
        buf = n00b_test_elf_phtab_adjustment(false, false, true, false, false);
        break;
    case N00B_TEST_ELF_GEN_PHTAB_ADJUST_AT_EOF:
        buf = n00b_test_elf_phtab_adjustment(false, false, false, true, false);
        break;
    case N00B_TEST_ELF_GEN_LOADABLE_RELOCATE_DIRECT:
        buf = n00b_test_elf_minimal_exec(0x400080, 0, 0x400000, 512, 512,
                                         true, false, true, false);
        break;
    case N00B_TEST_ELF_GEN_LOADABLE_RELOCATE_OVERLAY:
        buf = n00b_test_elf_minimal_exec(0x400080, 0, 0x400000, 512, 512,
                                         true, false, true, true);
        break;
    case N00B_TEST_ELF_GEN_LOADABLE_RELOCATE_ADDRESS_OVERFLOW:
        buf = n00b_test_elf_loadable_relocate_address_overflow();
        break;
    }

    if (buf != nullptr) {
        n00b_test_elf_apply_target_mutation(buf, test_case->target_mutation);
    }

    return buf;
}

/**
 * @file objfile_macho_casegen.h
 * @brief Test-local Mach-O 64-bit fixture generator for object-file
 *        known answers.
 *
 * The Mach-O analog of `objfile_elf_casegen.h`. Generates small,
 * deterministic, host-neutral Mach-O byte buffers exercising a handful
 * of structural shapes (load-command slack, a segment ordered after
 * `__LINKEDIT`, signature present/absent, and a two-slice fat binary)
 * for the Mach-O parser and future rewrite-admission tests. The helpers
 * are intentionally local to unit tests; production layout analysis
 * belongs under `compiler/objfile/`.
 *
 * Per n00b-api-guidelines § 1 (and macwrap DECISIONS.md D-018), this
 * test-local fixture-scaffolding header may use header-only libc for
 * raw byte work (`<stdint.h>`, `<stdbool.h>`, `<string.h>`, `memcpy`,
 * `strcmp`, fixed-width int types), matching the established
 * `objfile_elf_casegen.h` precedent. The exemption is narrow: it covers
 * only this scaffolding (never linked into the runtime library); the
 * code under test and every `n00b_*` call still use the n00b surface
 * (result/option handling, `n00b_buffer_t`, etc.).
 *
 * Related modules:
 * - `compiler/objfile/macho.h`        — the parsed types + parse API.
 * - `compiler/objfile/macho_build.h`  — the builder used by the cases.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "n00b.h"
#include "core/buffer.h"
#include "adt/result.h"
#include "compiler/objfile/macho.h"
#include "compiler/objfile/macho_build.h"

// ============================================================================
// Case-state lattice (mirrors objfile_elf_casegen.h:43-49, Mach-O subset).
// ============================================================================

typedef enum {
    N00B_TEST_MACHO_CASE_KNOWN,
    N00B_TEST_MACHO_CASE_EXPLORE,
    N00B_TEST_MACHO_CASE_PENDING,
    N00B_TEST_MACHO_CASE_RETIRED,
} n00b_test_macho_case_state_t;

// ============================================================================
// Parse expectation.
// ============================================================================

typedef enum {
    N00B_TEST_MACHO_PARSE_OK,
    N00B_TEST_MACHO_PARSE_REJECT,
} n00b_test_macho_parse_expect_t;

// ============================================================================
// Structural property each case asserts (the "shape").
// ============================================================================

typedef enum {
    N00B_TEST_MACHO_SHAPE_LC_SLACK,
    N00B_TEST_MACHO_SHAPE_LINKEDIT_NOT_LAST,
    N00B_TEST_MACHO_SHAPE_SIG_PRESENT,
    N00B_TEST_MACHO_SHAPE_SIG_ABSENT,
    N00B_TEST_MACHO_SHAPE_FAT_2SLICE,
} n00b_test_macho_shape_t;

// ============================================================================
// Generators (one per fixture shape).
//
// SIG_PRESENT has no generator: `n00b_macho_build` has no signature
// emitter, so that shape is loaded from the committed ad-hoc-signed
// fixture `test/unit/data/hello_signed_arm64.macho`. It is represented
// here by N00B_TEST_MACHO_GEN_SIG_PRESENT_FIXTURE, which
// `n00b_test_macho_build_case` declines to synthesize.
// ============================================================================

typedef enum {
    N00B_TEST_MACHO_GEN_LC_SLACK,
    N00B_TEST_MACHO_GEN_LINKEDIT_NOT_LAST,
    N00B_TEST_MACHO_GEN_SIG_PRESENT_FIXTURE,
    N00B_TEST_MACHO_GEN_SIG_ABSENT,
    N00B_TEST_MACHO_GEN_FAT_2SLICE,
} n00b_test_macho_generator_t;

// ============================================================================
// Case descriptor.
// ============================================================================

typedef struct {
    const char                     *name;
    n00b_test_macho_case_state_t    state;
    n00b_test_macho_generator_t     generator;
    n00b_test_macho_parse_expect_t  expect_parse;
    const char                     *expect_reason;
    n00b_test_macho_shape_t         shape;
    const char                     *description;
} n00b_test_macho_case_t;

static const n00b_test_macho_case_t n00b_test_macho_cases[] = {
    {
        .name          = "lc_slack",
        .state         = N00B_TEST_MACHO_CASE_KNOWN,
        .generator     = N00B_TEST_MACHO_GEN_LC_SLACK,
        .expect_parse  = N00B_TEST_MACHO_PARSE_OK,
        .expect_reason = "ok",
        .shape         = N00B_TEST_MACHO_SHAPE_LC_SLACK,
        .description   = "First segment file offset sits strictly after the "
                         "load-command region end (page-aligned slack).",
    },
    {
        .name          = "linkedit_not_last",
        .state         = N00B_TEST_MACHO_CASE_KNOWN,
        .generator     = N00B_TEST_MACHO_GEN_LINKEDIT_NOT_LAST,
        .expect_parse  = N00B_TEST_MACHO_PARSE_OK,
        .expect_reason = "ok",
        .shape         = N00B_TEST_MACHO_SHAPE_LINKEDIT_NOT_LAST,
        .description   = "A non-__LINKEDIT segment is ordered after "
                         "__LINKEDIT in file order.",
    },
    {
        .name          = "sig_present",
        .state         = N00B_TEST_MACHO_CASE_KNOWN,
        .generator     = N00B_TEST_MACHO_GEN_SIG_PRESENT_FIXTURE,
        .expect_parse  = N00B_TEST_MACHO_PARSE_OK,
        .expect_reason = "ok",
        .shape         = N00B_TEST_MACHO_SHAPE_SIG_PRESENT,
        .description   = "Committed ad-hoc-signed arm64 fixture carries an "
                         "LC_CODE_SIGNATURE.",
    },
    {
        .name          = "sig_absent",
        .state         = N00B_TEST_MACHO_CASE_KNOWN,
        .generator     = N00B_TEST_MACHO_GEN_SIG_ABSENT,
        .expect_parse  = N00B_TEST_MACHO_PARSE_OK,
        .expect_reason = "ok",
        .shape         = N00B_TEST_MACHO_SHAPE_SIG_ABSENT,
        .description   = "Builder output (unsigned) carries no code "
                         "signature.",
    },
    {
        .name          = "fat_2slice",
        .state         = N00B_TEST_MACHO_CASE_KNOWN,
        .generator     = N00B_TEST_MACHO_GEN_FAT_2SLICE,
        .expect_parse  = N00B_TEST_MACHO_PARSE_OK,
        .expect_reason = "ok",
        .shape         = N00B_TEST_MACHO_SHAPE_FAT_2SLICE,
        .description   = "Two-slice fat/universal binary; each slice parses.",
    },
};

static const size_t n00b_test_macho_case_count =
    sizeof(n00b_test_macho_cases) / sizeof(n00b_test_macho_cases[0]);

// ============================================================================
// Helpers (mirror the ELF casegen surface).
// ============================================================================

static inline const char *
n00b_test_macho_case_state_name(n00b_test_macho_case_state_t state)
{
    switch (state) {
    case N00B_TEST_MACHO_CASE_KNOWN:
        return "known";
    case N00B_TEST_MACHO_CASE_EXPLORE:
        return "explore";
    case N00B_TEST_MACHO_CASE_PENDING:
        return "pending";
    case N00B_TEST_MACHO_CASE_RETIRED:
        return "retired";
    }

    return "unknown";
}

static inline const char *
n00b_test_macho_shape_name(n00b_test_macho_shape_t shape)
{
    switch (shape) {
    case N00B_TEST_MACHO_SHAPE_LC_SLACK:
        return "lc-slack";
    case N00B_TEST_MACHO_SHAPE_LINKEDIT_NOT_LAST:
        return "linkedit-not-last";
    case N00B_TEST_MACHO_SHAPE_SIG_PRESENT:
        return "sig-present";
    case N00B_TEST_MACHO_SHAPE_SIG_ABSENT:
        return "sig-absent";
    case N00B_TEST_MACHO_SHAPE_FAT_2SLICE:
        return "fat-2slice";
    }

    return "unknown";
}

static inline const n00b_test_macho_case_t *
n00b_test_macho_case_by_name(const char *name)
{
    for (size_t i = 0; i < n00b_test_macho_case_count; i++) {
        if (strcmp(n00b_test_macho_cases[i].name, name) == 0) {
            return &n00b_test_macho_cases[i];
        }
    }

    return nullptr;
}

// ============================================================================
// Little-endian writers (Mach-O 64-bit is little-endian on arm64/x86-64).
// ============================================================================

static inline void
n00b_test_macho_put32(uint8_t *p, uint32_t v)
{
    memcpy(p, &v, sizeof(v));
}

static inline void
n00b_test_macho_put64(uint8_t *p, uint64_t v)
{
    memcpy(p, &v, sizeof(v));
}

// ============================================================================
// Case builders + dispatch.
//
// Header-only and `static`, mirroring `objfile_elf_casegen.h`'s
// `n00b_test_elf_case_generate`: the ELF casegen is consumed purely via
// `#include` (no separate compile unit is linked), and Mach-O follows
// the same shape so the always-run harness can ride the existing
// `'macho'` target without editing the test foreach. The companion
// `objfile_macho_casegen.c` is a thin TU that `#include`s this header so
// the implementation is also exercised as a standalone compile.
//
// `n00b_test_macho_build_case` returns Ok(buffer) for the four
// synthesizable shapes. For N00B_TEST_MACHO_GEN_SIG_PRESENT_FIXTURE it
// returns Err(N00B_ERR_BUILD): the builder cannot emit a signed fixture
// (no signature emitter), so the SIG_PRESENT shape is supplied by the
// committed ad-hoc-signed fixture instead.
//
// Fixed CPU type + fixed payload bytes keep the serialized output
// byte-reproducible regardless of host architecture (NFR-02 spirit). The
// LC_SLACK / SIG_ABSENT / FAT_2SLICE shapes go through the public build
// API; LINKEDIT_NOT_LAST is hand-assembled raw bytes because the build
// API always emits __LINKEDIT last and offers no way to place a user
// segment after it.
//
// Per n00b-api-guidelines § 1 / macwrap DECISIONS.md D-018, this
// test-local scaffolding may use header-only libc for raw byte work
// (`memcpy`, `strlen`, fixed-width ints); every `n00b_*` call still uses
// the n00b surface (result/option, `n00b_buffer_t`, `.allocator`-aware
// constructors).
// ============================================================================

#include "compiler/objfile/macho_types.h"

// Fixed, host-neutral CPU identity for every synthesized fixture. arm64
// is the project's primary target; keeping it constant (independent of
// the build host) is what makes the byte output reproducible.
#define N00B_TEST_MACHO_CPUTYPE      CPU_TYPE_ARM64
#define N00B_TEST_MACHO_CPUSUBTYPE   CPU_SUBTYPE_ARM64_ALL

// Raw LC_SEGMENT_64 geometry (matches write_segment_command in
// macho_build.c): cmd(4) cmdsize(4) segname[16] vmaddr(8) vmsize(8)
// fileoff(8) filesize(8) maxprot(4) initprot(4) nsects(4) flags(4).
#define N00B_TEST_MACHO_HDR_SIZE        32
#define N00B_TEST_MACHO_SEG_CMD_SIZE    72
#define N00B_TEST_MACHO_PAGE            0x4000ULL

// ----------------------------------------------------------------------------
// LC_SLACK — first segment file offset sits strictly after the LC region.
//
// `n00b_macho_build` always page-aligns the first non-__TEXT segment's
// file offset to a 16K boundary, well past `header + sizeofcmds`, so the
// natural builder output already exhibits the LC-slack shape. We add a
// __DATA segment so there is a segment whose file offset is provably
// past the load-command region end.
// ----------------------------------------------------------------------------

static n00b_result_t(n00b_buffer_t *)
n00b_test_macho_build_lc_slack(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(N00B_TEST_MACHO_CPUTYPE,
                                                     N00B_TEST_MACHO_CPUSUBTYPE,
                                                     MH_EXECUTE);

    n00b_macho_add_segment(bin, "__TEXT", 5, 5);   // r-x

    n00b_macho_segment_t *data = n00b_macho_add_segment(bin, "__DATA", 3, 3);
    n00b_macho_section_t *sec  = n00b_macho_add_section(data,
                                                        "__data",
                                                        "__DATA",
                                                        0,
                                                        3);  // align 2^3 = 8

    static const uint8_t payload[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    };
    sec->content = n00b_buffer_from_bytes((char *)payload, sizeof(payload));

    n00b_macho_set_entry(bin, 0, 0);

    return n00b_macho_build(bin);
}

// ----------------------------------------------------------------------------
// SIG_ABSENT — builder output carries no code signature.
// ----------------------------------------------------------------------------

static n00b_result_t(n00b_buffer_t *)
n00b_test_macho_build_sig_absent(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(N00B_TEST_MACHO_CPUTYPE,
                                                     N00B_TEST_MACHO_CPUSUBTYPE,
                                                     MH_EXECUTE);

    n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    n00b_macho_set_entry(bin, 0, 0);

    // The builder never emits an LC_CODE_SIGNATURE, so the parsed
    // binary's code_signature stays nullptr.
    return n00b_macho_build(bin);
}

// ----------------------------------------------------------------------------
// FAT_2SLICE — two-slice fat/universal binary.
// ----------------------------------------------------------------------------

static n00b_result_t(n00b_buffer_t *)
n00b_test_macho_build_fat_2slice(void)
{
    // Two thin binaries with distinct CPU subtypes so the fat container
    // has two well-formed slices. Both stay arm64 (host-neutral); the
    // subtype distinguishes them.
    n00b_macho_binary_t *slice0 = n00b_macho_binary_new(N00B_TEST_MACHO_CPUTYPE,
                                                        CPU_SUBTYPE_ARM64_ALL,
                                                        MH_EXECUTE);
    n00b_macho_add_segment(slice0, "__TEXT", 5, 5);
    n00b_macho_set_entry(slice0, 0, 0);

    n00b_macho_binary_t *slice1 = n00b_macho_binary_new(N00B_TEST_MACHO_CPUTYPE,
                                                        CPU_SUBTYPE_ARM64_ALL + 1,
                                                        MH_EXECUTE);
    n00b_macho_add_segment(slice1, "__TEXT", 5, 5);
    n00b_macho_set_entry(slice1, 0, 0);

    n00b_macho_binary_t *binaries[2] = {slice0, slice1};

    n00b_macho_fat_t fat = {
        .binaries = binaries,
        .count    = 2,
    };

    return n00b_macho_build_fat(&fat);
}

// ----------------------------------------------------------------------------
// LINKEDIT_NOT_LAST — a segment ordered after __LINKEDIT in file order.
//
// The build API cannot express this: `n00b_macho_build` always lays out
// `__LINKEDIT` last. So we hand-assemble a minimal, well-formed Mach-O
// with three LC_SEGMENT_64 commands — __TEXT, __LINKEDIT, then __DATA —
// where __DATA's file offset is greater than __LINKEDIT's. The parser
// accepts the structure (parse OK); the harness proves the property from
// the parsed segment file offsets and names.
//
// Layout (all 16K page-aligned so it resembles real loader output):
//   [0]      mach_header_64                 32 bytes
//   [32]     LC_SEGMENT_64 __TEXT           72 bytes (fileoff 0)
//   [104]    LC_SEGMENT_64 __LINKEDIT       72 bytes (fileoff 0x4000)
//   [176]    LC_SEGMENT_64 __DATA           72 bytes (fileoff 0x8000)
//   total size = 0xc000 (three 16K pages of file content)
// ----------------------------------------------------------------------------

static inline void
n00b_test_macho_write_seg_cmd(uint8_t    *p,
                              const char *name,
                              uint64_t    vmaddr,
                              uint64_t    vmsize,
                              uint64_t    fileoff,
                              uint64_t    filesize,
                              uint32_t    maxprot,
                              uint32_t    initprot)
{
    n00b_test_macho_put32(p + 0, LC_SEGMENT_64);
    n00b_test_macho_put32(p + 4, N00B_TEST_MACHO_SEG_CMD_SIZE);

    // segname[16], zero-padded.
    memset(p + 8, 0, 16);
    size_t name_len = strlen(name);
    if (name_len > 16) {
        name_len = 16;
    }
    memcpy(p + 8, name, name_len);

    n00b_test_macho_put64(p + 24, vmaddr);
    n00b_test_macho_put64(p + 32, vmsize);
    n00b_test_macho_put64(p + 40, fileoff);
    n00b_test_macho_put64(p + 48, filesize);
    n00b_test_macho_put32(p + 56, maxprot);
    n00b_test_macho_put32(p + 60, initprot);
    n00b_test_macho_put32(p + 64, 0);  // nsects
    n00b_test_macho_put32(p + 68, 0);  // flags
}

static n00b_result_t(n00b_buffer_t *)
n00b_test_macho_build_linkedit_not_last(void)
{
    const uint64_t text_off     = 0;
    const uint64_t linkedit_off = N00B_TEST_MACHO_PAGE;            // 0x4000
    const uint64_t data_off     = N00B_TEST_MACHO_PAGE * 2;        // 0x8000
    const size_t   total_size   = (size_t)(N00B_TEST_MACHO_PAGE * 3); // 0xc000

    n00b_buffer_t *buf = n00b_buffer_new((int64_t)total_size);
    n00b_buffer_resize(buf, (uint64_t)total_size);

    uint8_t *p = (uint8_t *)buf->data;

    // mach_header_64
    n00b_test_macho_put32(p + 0, MH_MAGIC_64);
    n00b_test_macho_put32(p + 4, N00B_TEST_MACHO_CPUTYPE);
    n00b_test_macho_put32(p + 8, N00B_TEST_MACHO_CPUSUBTYPE);
    n00b_test_macho_put32(p + 12, MH_EXECUTE);
    n00b_test_macho_put32(p + 16, 3);                       // ncmds
    n00b_test_macho_put32(p + 20, 3 * N00B_TEST_MACHO_SEG_CMD_SIZE); // sizeofcmds
    n00b_test_macho_put32(p + 24, MH_PIE);                  // flags
    // reserved (p + 28) stays zero.

    // __TEXT (fileoff 0, covers the header + load commands).
    n00b_test_macho_write_seg_cmd(p + N00B_TEST_MACHO_HDR_SIZE,
                                  "__TEXT",
                                  0x100000000ULL,
                                  N00B_TEST_MACHO_PAGE,
                                  text_off,
                                  N00B_TEST_MACHO_PAGE,
                                  5, 5);

    // __LINKEDIT placed BEFORE __DATA in file order.
    n00b_test_macho_write_seg_cmd(
        p + N00B_TEST_MACHO_HDR_SIZE + N00B_TEST_MACHO_SEG_CMD_SIZE,
        "__LINKEDIT",
        0x100000000ULL + linkedit_off,
        N00B_TEST_MACHO_PAGE,
        linkedit_off,
        N00B_TEST_MACHO_PAGE,
        1, 1);

    // __DATA placed AFTER __LINKEDIT in file order (the property proof).
    n00b_test_macho_write_seg_cmd(
        p + N00B_TEST_MACHO_HDR_SIZE + 2 * N00B_TEST_MACHO_SEG_CMD_SIZE,
        "__DATA",
        0x100000000ULL + data_off,
        N00B_TEST_MACHO_PAGE,
        data_off,
        N00B_TEST_MACHO_PAGE,
        3, 3);

    return n00b_result_ok(n00b_buffer_t *, buf);
}

// ----------------------------------------------------------------------------
// Dispatch.
// ----------------------------------------------------------------------------

static n00b_result_t(n00b_buffer_t *)
n00b_test_macho_build_case(n00b_test_macho_generator_t generator)
{
    switch (generator) {
    case N00B_TEST_MACHO_GEN_LC_SLACK:
        return n00b_test_macho_build_lc_slack();
    case N00B_TEST_MACHO_GEN_LINKEDIT_NOT_LAST:
        return n00b_test_macho_build_linkedit_not_last();
    case N00B_TEST_MACHO_GEN_SIG_ABSENT:
        return n00b_test_macho_build_sig_absent();
    case N00B_TEST_MACHO_GEN_FAT_2SLICE:
        return n00b_test_macho_build_fat_2slice();
    case N00B_TEST_MACHO_GEN_SIG_PRESENT_FIXTURE:
        // No signature emitter in the builder; SIG_PRESENT is supplied
        // by the committed ad-hoc-signed fixture instead.
        return n00b_result_err(n00b_buffer_t *, N00B_ERR_BUILD);
    }

    return n00b_result_err(n00b_buffer_t *, N00B_ERR_BUILD);
}

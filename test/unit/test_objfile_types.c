#include <stdio.h>
#include <assert.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "adt/result.h"
#include "adt/option.h"
#include "compiler/objfile/types.h"

// ============================================================================
// Error codes
// ============================================================================

static void
test_error_values(void)
{
    // Error codes should all be negative and distinct.
    assert(N00B_OK == 0);
    assert(N00B_ERR_READ < 0);
    assert(N00B_ERR_NOT_FOUND < 0);
    assert(N00B_ERR_CORRUPTED < 0);
    assert(N00B_ERR_PARSE < 0);
    assert(N00B_ERR_BUILD < 0);
    assert(N00B_ERR_NOT_SUPPORTED < 0);
    assert(N00B_ERR_OUT_OF_BOUNDS < 0);

    // All distinct.
    assert(N00B_ERR_READ != N00B_ERR_NOT_FOUND);
    assert(N00B_ERR_CORRUPTED != N00B_ERR_PARSE);
    assert(N00B_ERR_BUILD != N00B_ERR_NOT_SUPPORTED);

    printf("  [PASS] error_values\n");
}

// ============================================================================
// Format enum
// ============================================================================

static void
test_format_enum(void)
{
    assert(N00B_FMT_UNKNOWN == 0);
    assert(N00B_FMT_ELF != N00B_FMT_MACHO);
    assert(N00B_FMT_ELF != N00B_FMT_UNKNOWN);

    printf("  [PASS] format_enum\n");
}

// ============================================================================
// Endian enum
// ============================================================================

static void
test_endian_enum(void)
{
    assert(N00B_ENDIAN_LITTLE == 0);
    assert(N00B_ENDIAN_BIG == 1);

    printf("  [PASS] endian_enum\n");
}

// ============================================================================
// Arch enum
// ============================================================================

static void
test_arch_enum(void)
{
    assert(N00B_ARCH_UNKNOWN == 0);
    assert(N00B_ARCH_X86 != N00B_ARCH_X86_64);
    assert(N00B_ARCH_ARM != N00B_ARCH_ARM64);

    printf("  [PASS] arch_enum\n");
}

// ============================================================================
// Result types with objfile error codes
// ============================================================================

static void
test_result_with_objfile_errors(void)
{
    // A result carrying a bool, with an objfile error code.
    n00b_result_t(bool) ok = n00b_result_ok(bool, true);
    assert(n00b_result_is_ok(ok));
    assert(n00b_result_get(ok) == true);

    n00b_result_t(bool) err = n00b_result_err(bool, N00B_ERR_OUT_OF_BOUNDS);
    assert(n00b_result_is_err(err));
    assert(n00b_result_get_err(err) == N00B_ERR_OUT_OF_BOUNDS);

    // uint64_t result.
    n00b_result_t(uint64_t) u64_ok = n00b_result_ok(uint64_t, 0xDEADBEEF);
    assert(n00b_result_get(u64_ok) == 0xDEADBEEF);

    n00b_result_t(uint64_t) u64_err = n00b_result_err(uint64_t, N00B_ERR_READ);
    assert(n00b_result_get_err(u64_err) == N00B_ERR_READ);

    printf("  [PASS] result_with_objfile_errors\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running types tests...\n");

    test_error_values();
    test_format_enum();
    test_endian_enum();
    test_arch_enum();
    test_result_with_objfile_errors();

    printf("All types tests passed.\n");
    n00b_shutdown();
    return 0;
}

/**
 * @file test_n00b_eval.c
 * @brief WP-009 Phase 3 — libn00b embedded-eval API smoke.
 *
 * Six cases:
 *   1. `r"true"`  on `r"int"`  → returns true regardless of arg.
 *   2. `r"false"` on `r"int"`  → returns false regardless of arg.
 *   3. `r"test_double_int(arg) > 10"` on `r"int"`, after
 *      `n00b_ffi_install_simple` of a C `int64_t -> int64_t`
 *      doubler. arg=6 → 12 > 10 → true; arg=4 → 8 > 10 → false.
 *   4. `r"arg == 42"` on `r"int"` proves the generated wrapper can
 *      resolve and evaluate its bound argument without an FFI call.
 *   5. Two independent sessions can be created and used in one process
 *      without reparsing `n00b.bnf` into an unbounded BNF/PWZ path.
 *   6. A malformed predicate returns `N00B_EVAL_ERR_PARSE` through the
 *      bounded predicate parser instead of falling into Earley recovery.
 *
 * Case 3 exercises the libn00b plumbing that the naudit-side test
 * also relies on: an `n00b_ffi_install_simple`-registered C symbol
 * being callable from a JIT'd predicate expression.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "n00b/embed_ffi.h"
#include "n00b/eval.h"
#include "util/assert.h"

// ============================================================================
// Helper FFI target
//
// `n00b_ffi_install_simple` resolves the C symbol at install time. On Unix it
// uses `dlsym(RTLD_DEFAULT, ...)`, so this function must have external linkage.
// Windows executables do not export local test symbols by default, so the test
// registers the address explicitly before installing the name-based binding.
// ============================================================================

int64_t
test_double_int(int64_t x)
{
    return x * 2;
}

// ============================================================================
// Cases
// ============================================================================

static void
test_compile_true(n00b_eval_session_t *s)
{
    auto r = n00b_eval_compile_predicate(s, r"true", r"int");

    if (n00b_result_is_err(r)) {
        n00b_eval_err_t e = (n00b_eval_err_t)n00b_result_get_err(r);
        fprintf(stderr,
                "  [FAIL] compile true: code=%d (%.*s)\n",
                (int)e,
                (int)n00b_eval_err_str(e)->u8_bytes,
                n00b_eval_err_str(e)->data);
    }
    assert(n00b_result_is_ok(r));

    n00b_eval_predicate_fn_t fn = n00b_result_get(r);
    assert(fn);

    bool got = fn((void *)(intptr_t)0);
    assert(got == true);

    printf("  [PASS] compile_true (returns true)\n");
}

static void
test_compile_false(n00b_eval_session_t *s)
{
    auto r = n00b_eval_compile_predicate(s, r"false", r"int");

    if (n00b_result_is_err(r)) {
        n00b_eval_err_t e = (n00b_eval_err_t)n00b_result_get_err(r);
        fprintf(stderr,
                "  [FAIL] compile false: code=%d (%.*s)\n",
                (int)e,
                (int)n00b_eval_err_str(e)->u8_bytes,
                n00b_eval_err_str(e)->data);
    }
    assert(n00b_result_is_ok(r));

    n00b_eval_predicate_fn_t fn = n00b_result_get(r);
    assert(fn);

    bool got = fn((void *)(intptr_t)0);
    assert(got == false);

    printf("  [PASS] compile_false (returns false)\n");
}

static void
test_compile_arg_compare(n00b_eval_session_t *s)
{
    auto r = n00b_eval_compile_predicate(s, r"arg == 42", r"int");

    n00b_require(n00b_result_is_ok(r),
                 "compile arg compare predicate should succeed");

    n00b_eval_predicate_fn_t fn = n00b_result_get(r);
    n00b_require(fn != nullptr, "compiled arg compare predicate is null");

    n00b_require(fn((void *)(intptr_t)42) == true,
                 "arg compare should accept 42");
    n00b_require(fn((void *)(intptr_t)41) == false,
                 "arg compare should reject 41");
}

static void
test_ffi_double_then_compare(n00b_eval_session_t *s)
{
    // Install the doubler under the n00b name `test_double_int`.
    // Signature: (int) -> int, matching the C signature for an
    // (int64_t)->int64_t.
    n00b_cg_session_t *cg = n00b_eval_session_cg(s);
    const char *param_types[] = {"int"};

#ifdef _WIN32
    bool symbol_registered =
        n00b_ffi_register_symbol("test_double_int", (void *)test_double_int);
    assert(symbol_registered);
#endif

    bool installed = n00b_ffi_install_simple(cg,
                                              "test_double_int",
                                              "test_double_int",
                                              param_types,
                                              1,
                                              "int");

    if (!installed) {
        fprintf(stderr, "  [FAIL] n00b_ffi_install_simple "
                        "could not register test_double_int\n");
    }
    assert(installed);

    // Compile a predicate referencing the registered symbol.
    auto r = n00b_eval_compile_predicate(s,
                                         r"test_double_int(arg) > 10",
                                         r"int");

    if (n00b_result_is_err(r)) {
        n00b_eval_err_t e = (n00b_eval_err_t)n00b_result_get_err(r);
        fprintf(stderr,
                "  [FAIL] compile ffi expression: code=%d (%.*s)\n",
                (int)e,
                (int)n00b_eval_err_str(e)->u8_bytes,
                n00b_eval_err_str(e)->data);
    }
    assert(n00b_result_is_ok(r));

    n00b_eval_predicate_fn_t fn = n00b_result_get(r);
    assert(fn);

    // 6 → 12 > 10 → true
    bool got_true = fn((void *)(intptr_t)6);
    assert(got_true == true);

    // 4 → 8 > 10 → false
    bool got_false = fn((void *)(intptr_t)4);
    assert(got_false == false);

    printf("  [PASS] ffi_double_then_compare (6→true, 4→false)\n");
}

static void
test_parse_failure_is_bounded(n00b_eval_session_t *s)
{
    auto r = n00b_eval_compile_predicate(s, r".", r"int");

    n00b_require(n00b_result_is_err(r),
                 "malformed eval predicate should fail to compile");
    n00b_require((n00b_eval_err_t)n00b_result_get_err(r)
                 == N00B_EVAL_ERR_PARSE,
                 "malformed eval predicate should return parse error");
}

static void
test_two_independent_sessions(void)
{
    auto first = n00b_eval_session_new();
    n00b_require(n00b_result_is_ok(first),
                 "first independent eval session should initialize");

    n00b_eval_session_t *s1 = n00b_result_get(first);
    n00b_require(s1 != nullptr, "first independent eval session is null");

    auto c1 = n00b_eval_compile_predicate(s1, r"true", r"int");
    n00b_require(n00b_result_is_ok(c1),
                 "first independent eval predicate should compile");

    n00b_eval_predicate_fn_t fn1 = n00b_result_get(c1);
    n00b_require(fn1 != nullptr, "first independent predicate is null");
    n00b_require(fn1((void *)(intptr_t)0) == true,
                 "first independent predicate should return true");

    n00b_eval_session_free(s1);

    auto second = n00b_eval_session_new();
    n00b_require(n00b_result_is_ok(second),
                 "second independent eval session should initialize");

    n00b_eval_session_t *s2 = n00b_result_get(second);
    n00b_require(s2 != nullptr, "second independent eval session is null");

    auto c2 = n00b_eval_compile_predicate(s2, r"arg == 7", r"int");
    n00b_require(n00b_result_is_ok(c2),
                 "second independent eval predicate should compile");

    n00b_eval_predicate_fn_t fn2 = n00b_result_get(c2);
    n00b_require(fn2 != nullptr, "second independent predicate is null");
    n00b_require(fn2((void *)(intptr_t)7) == true,
                 "second independent predicate should accept 7");
    n00b_require(fn2((void *)(intptr_t)8) == false,
                 "second independent predicate should reject 8");

    n00b_eval_session_free(s2);
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    auto sr = n00b_eval_session_new();

    if (n00b_result_is_err(sr)) {
        n00b_eval_err_t e = (n00b_eval_err_t)n00b_result_get_err(sr);
        fprintf(stderr,
                "  [FAIL] session_new: code=%d (%.*s)\n",
                (int)e,
                (int)n00b_eval_err_str(e)->u8_bytes,
                n00b_eval_err_str(e)->data);
        return 2;
    }

    n00b_eval_session_t *s = n00b_result_get(sr);
    assert(s);

    // Case 3 installs an FFI binding via `n00b_ffi_install_simple`,
    // which emits a fresh MIR wrapper into the session's currently
    // active module. After `n00b_eval_compile_predicate` has run,
    // that module is `MIR_finish_module`'d and MIR will refuse new
    // imports (the error surface is "import outside module" on stderr).
    // Running the FFI-bound case FIRST is the conservative ordering;
    // the trivial true/false cases still exercise the post-FFI session.
    test_ffi_double_then_compare(s);
    test_compile_true(s);
    test_compile_false(s);
    test_compile_arg_compare(s);
    test_parse_failure_is_bounded(s);

    n00b_eval_session_free(s);
    test_two_independent_sessions();

    printf("All n00b_eval smoke tests passed.\n");
    return 0;
}

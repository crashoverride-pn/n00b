/*
 * WP-021 regression test — the C preprocessor pre-pass must not be
 * lossy.
 *
 * Bug: when the engine's `cc -E` pre-pass was ON (the default for
 * `.c`), text-predicate filters (e.g. the NULL rule's
 * `is_null_keyword` / `arg.text_equals("NULL")`) silently dropped
 * real violations. The engine resolves a match's `.text` by walking
 * `src_text` using the parse tree's token line/column coordinates;
 * `src_text` was built from the RAW on-disk source while the parse
 * ran over the PREPROCESSED buffer. The preprocessor reflows
 * whitespace (`int *p` -> `int * p`), so a match's column in the
 * preprocessed parse tree did not index the same byte in the raw
 * source -> `.text` resolved to the wrong/empty slice -> the
 * text predicate failed -> the violation was dropped. A false
 * negative for a standards-enforcement tool.
 *
 * This test loads the canonical NULL rule (with its real
 * text-predicate filter) and audits three fixtures with
 * preprocessing ON (default) and OFF (N00B_NAUDIT_SKIP_PREPROCESS=1),
 * asserting:
 *   (a) the ON path reports the full expected violation count
 *       (not lossy); and
 *   (b) ON count == OFF count for every fixture.
 *
 * Fixtures and expected counts (observed from the checked-in files,
 * not invented, per the cross-project numeric-claims rule):
 *   - fixture_null_oneline.c : 1 NULL  (single-line; the case that
 *                                       lost ALL violations pre-fix)
 *   - fixture_null_multi.c   : 3 NULLs (multiple on one line)
 *   - fixture_null.c         : 2 NULLs (the original Phase 3 fixture;
 *                                       lost the earliest pre-fix)
 *
 * Bootstrap shape mirrors `test_naudit_filter_e2e.c` per the relaxed
 * test convention (libc <assert.h>/<stdio.h> allowed for harness
 * scaffolding; n00b_init_simple first). The .c fixtures contain
 * `NULL` deliberately as PARSE TARGETS — the n00b-api-guidelines
 * § 2.1 rule does not apply to them.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_portability.h"

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"

#include "naudit/naudit.h"
#include "naudit/engine.h"
#include "naudit/errors.h"
#include "naudit/guidance.h"
#include "naudit/rule.h"
#include "naudit/violation.h"

#ifndef N00B_AUDIT_TEST_FIXTURE_DIR
#error "N00B_AUDIT_TEST_FIXTURE_DIR must be set by the build (see meson.build)"
#endif

static n00b_string_t *
fixture_path(const char *fname)
{
    char buf[1024];
    int  n = snprintf(buf, sizeof(buf), "%s/%s",
                      N00B_AUDIT_TEST_FIXTURE_DIR, fname);
    assert(n > 0 && (size_t)n < sizeof(buf));
    return n00b_string_from_cstr(buf);
}

static n00b_audit_guidance_t *
load_null_guidance(void)
{
    n00b_string_t *p = fixture_path("guidance_preprocess_null.bnf");
    auto r = n00b_audit_load_guidance(p);
    if (n00b_result_is_err(r)) {
        fprintf(stderr,
                "  load_guidance failed: code=%d (%.*s)\n",
                n00b_result_get_err(r),
                (int)n00b_audit_err_str(n00b_result_get_err(r))->u8_bytes,
                n00b_audit_err_str(n00b_result_get_err(r))->data);
    }
    assert(n00b_result_is_ok(r));
    n00b_audit_guidance_t *g = n00b_result_get(r);
    assert(!!g);
    assert(!!g->rules);
    assert(n00b_list_len(*g->rules) == 1);
    printf("  [PASS] guidance loads NULL rule + filter\n");
    return g;
}

/*
 * Audit @p fname with preprocessing in the state selected by @p skip
 * (true => N00B_NAUDIT_SKIP_PREPROCESS=1 set; false => unset, so the
 * `cc -E` pre-pass runs). The env var is read via getenv() inside the
 * engine, so we toggle it per call.
 */
static int64_t
count_violations(n00b_audit_engine_t *engine,
                 const char          *fname,
                 bool                 skip)
{
    if (skip) {
        setenv("N00B_NAUDIT_SKIP_PREPROCESS", "1", 1);
    }
    else {
        unsetenv("N00B_NAUDIT_SKIP_PREPROCESS");
    }

    n00b_string_t *path = fixture_path(fname);
    auto r = n00b_audit_engine_check_file(engine, path);
    if (n00b_result_is_err(r)) {
        fprintf(stderr,
                "  check_file(%s, skip=%d) failed: code=%d (%.*s)\n",
                fname, (int)skip,
                n00b_result_get_err(r),
                (int)n00b_audit_err_str(n00b_result_get_err(r))->u8_bytes,
                n00b_audit_err_str(n00b_result_get_err(r))->data);
    }
    assert(n00b_result_is_ok(r));
    n00b_list_t(n00b_audit_violation_t *) *vs = n00b_result_get(r);
    assert(!!vs);
    return n00b_list_len(*vs);
}

/*
 * Core regression assertion: for @p fname the ON (preprocess) path is
 * NOT lossy (== @p expected) and equals the OFF path. The bug
 * manifested as ON < OFF (single-line: ON=0 OFF=1; multi: ON=0 OFF=3;
 * fixture_null: ON=1 OFF=2).
 */
static void
assert_on_equals_off(n00b_audit_engine_t *engine,
                     const char          *fname,
                     int64_t              expected)
{
    int64_t off = count_violations(engine, fname, true);
    int64_t on  = count_violations(engine, fname, false);

    if (off != expected || on != expected || on != off) {
        fprintf(stderr,
                "  %s: ON=%lld OFF=%lld expected=%lld\n",
                fname, (long long)on, (long long)off,
                (long long)expected);
    }
    assert(off == expected);
    assert(on == expected);
    assert(on == off);
    printf("  [PASS] %s preprocess-on not lossy "
           "(ON=%lld OFF=%lld expected=%lld)\n",
           fname, (long long)on, (long long)off, (long long)expected);
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    n00b_audit_guidance_t *guidance = load_null_guidance();

    auto er = n00b_audit_engine_new(guidance);
    if (n00b_result_is_err(er)) {
        fprintf(stderr,
                "  engine_new failed: code=%d (%.*s)\n",
                n00b_result_get_err(er),
                (int)n00b_audit_err_str(n00b_result_get_err(er))->u8_bytes,
                n00b_audit_err_str(n00b_result_get_err(er))->data);
    }
    assert(n00b_result_is_ok(er));
    n00b_audit_engine_t *engine = n00b_result_get(er);
    assert(!!engine);
    printf("  [PASS] engine_new ok\n");

    assert_on_equals_off(engine, "fixture_null_oneline.c", 1);
    assert_on_equals_off(engine, "fixture_null_multi.c",   3);
    assert_on_equals_off(engine, "fixture_null.c",         2);

    printf("All n00b-audit WP-021 preprocess-not-lossy checks passed.\n");
    return 0;
}

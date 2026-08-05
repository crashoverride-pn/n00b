/*
 * WP-019 regression test — C string/char literal tokenization.
 *
 * Root cause (fixed in src/slay/c_tokenizer.c): the C tokenizer
 * emitted string literals under the token-type name `STRING_LIT`
 * and char literals under `CHAR_LIT`. Those are the *n00b-language*
 * grammar's literal-type spellings; the C grammar
 * (grammars/c_ncc.bnf) declares `%STRING` / `%CHAR`. Emitting a
 * literal-type name the grammar does not declare makes
 * `n00b_scan_emit` return `N00B_TOK_ERR_BAD_TYPE_NAME` and silently
 * drop the token, so every C string/char literal vanished from the
 * token stream. Constructs that always carry a string literal —
 * notably gcc/clang asm-labels (`int x __asm("y");`) — therefore
 * always failed to parse against the merged grammar.
 *
 * This test asserts BOTH directions:
 *   - The three asm-label spellings + plain string/char literals now
 *     parse (no `N00B_AUDIT_ERR_ENGINE_PARSE`).
 *   - The previously-passing control-flow / `__attribute__` /
 *     goto+label set still parses (guards against an over-broad fix).
 *
 * Hermetic: `N00B_NAUDIT_SKIP_PREPROCESS=1` is set so the engine
 * tokenizes + parses the fixture bytes directly instead of shelling
 * out to `ncc -E`. The fixtures contain no preprocessor directives,
 * so skipping the pre-pass changes nothing about what is parsed.
 *
 * Bootstrap shape mirrors test/unit/test_naudit_engine.c per the
 * relaxed test convention: libc <assert.h>/<stdio.h>/<stdlib.h> are
 * permitted for harness scaffolding (NCC.md "NO LIBC ALLOWED"
 * exemption for test files); main(argc, argv) + n00b_init_simple
 * first; fixture paths via the N00B_AUDIT_TEST_FIXTURE_DIR macro
 * (no hardcoded paths in C source — set by meson.build).
 *
 * The fixture .c files are TARGET INPUT the engine parses, not
 * n00b-audit source — the n00b-api-guidelines do not apply to them.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_portability.h"

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "adt/list.h"

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

/*
 * Build a minimal-but-valid guidance + engine. The single rule's
 * content is immaterial here — the test only cares whether the
 * target file PARSES, not which violations fire — but the engine
 * constructor requires at least one well-formed rule, so we reuse
 * the canonical NULL-rule shape from test_naudit_engine.c.
 */
static n00b_audit_engine_t *
build_engine(void)
{
    n00b_string_t *p = fixture_path("guidance_ok.bnf");
    auto           gr = n00b_audit_load_guidance(p);
    assert(n00b_result_is_ok(gr));

    n00b_audit_guidance_t *g = n00b_result_get(gr);
    assert(g != nullptr);
    assert(g->rules != nullptr);
    assert(n00b_list_len(*g->rules) == 1);

    n00b_audit_rule_t *rule = n00b_list_get(*g->rules, 0);
    assert(rule != nullptr);

    /*
     * The parse test is indifferent to which violations fire; it
     * only needs a guidance whose single rule constructs cleanly.
     * Add one alternative to the existing `provided_identifier` NT
     * and point `@violation_nt` at that same (base-grammar) NT, so
     * the engine's violation_nt-resolves-to-an-existing-NT check
     * passes without inventing a new NT.
     */
    rule->bnf_fragment = n00b_string_from_cstr(
        "<provided_identifier> ::= %\"NULL\"\n");
    rule->violation_nt = n00b_string_from_cstr("provided_identifier");

    auto er = n00b_audit_engine_new(g);
    assert(n00b_result_is_ok(er));
    n00b_audit_engine_t *engine = n00b_result_get(er);
    assert(engine != nullptr);
    return engine;
}

/*
 * Check that `fname` parses cleanly: the engine must return ok (a
 * violations list), NOT the N00B_AUDIT_ERR_ENGINE_PARSE error that a
 * merged-grammar parse failure surfaces.
 */
static void
assert_parses(n00b_audit_engine_t *engine, const char *fname)
{
    n00b_string_t *path = fixture_path(fname);
    auto           r    = n00b_audit_engine_check_file(engine, path);

    if (n00b_result_is_err(r)) {
        int e = n00b_result_get_err(r);
        fprintf(stderr,
                "  [FAIL] %s did not parse: code=%d (%.*s)\n",
                fname, e,
                (int)n00b_audit_err_str(e)->u8_bytes,
                n00b_audit_err_str(e)->data);
    }
    assert(n00b_result_is_ok(r));

    n00b_list_t(n00b_audit_violation_t *) *violations = n00b_result_get(r);
    assert(violations != nullptr);
    printf("  [PASS] %s parses (violations=%lld)\n",
           fname, (long long)n00b_list_len(*violations));
}

int
main(int argc, char *argv[])
{
    /* Tokenize/parse the fixture bytes directly — no ncc -E pre-pass.
     * setenv before n00b_init so the engine sees it on first check. */
    setenv("N00B_NAUDIT_SKIP_PREPROCESS", "1", 1);

    n00b_init_simple(argc, argv);

    n00b_audit_engine_t *engine = build_engine();

    /* Direction 1 — the WP-019 fix: string-bearing constructs parse. */
    assert_parses(engine, "fixture_asm_label.c");
    assert_parses(engine, "fixture_string_literal.c");

    /* Direction 2 — regression guard: the previously-passing set
     * (no string/char literals) must still parse. */
    assert_parses(engine, "fixture_control_flow.c");

    printf("All WP-019 parse-correctness regression checks passed.\n");
    return 0;
}

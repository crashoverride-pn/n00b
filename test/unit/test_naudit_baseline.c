/*
 * WP-011 Phase 1 — integration tests for the baseline workflow.
 *
 * Coverage:
 *   1. Hand-crafted exemption suppresses a known
 *      `fixture_null.c` violation:
 *      - Run the engine, capture the violation's hash + fingerprint.
 *      - Write an exemption file under
 *        `<tmp>/audit/exemptions/null.bnf` that matches.
 *      - Re-load guidance with the project root pointed at the
 *        tmp; verify the violation disappears.
 *   2. Baseline-finalize integration:
 *      - Pre-measure N from a fresh audit.
 *      - Run `n00b_audit_finalize_baseline`; assert the file
 *        contains N entries.
 *      - Re-load guidance + re-audit; assert zero violations.
 *      - Same + `--ignore-baseline` (via the setter); assert
 *        the N violations re-surface.
 *
 * The pre-measured N is recorded at runtime per the prompt
 * checklist item 5 — the test never hardcodes N.
 *
 * Layout. The tests create a private working directory under
 * `<fixture_dir>/tmp_baseline/` so they don't pollute the
 * checked-in fixture set. The audit-rules.bnf file used inside
 * that directory is a COPY of the in-tree
 * `test/fixtures/naudit/guidance_ok.bnf` patched to carry the
 * Phase 3-resolved NULL rule (the same patching the existing
 * `test_naudit_engine.c` performs in-memory).
 *
 * Bootstrap shape mirrors `test_naudit_engine.c`.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "test_portability.h"

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "text/strings/string_ops.h"

#include "naudit/naudit.h"
#include "naudit/engine.h"
#include "naudit/exemption.h"
#include "naudit/guidance.h"
#include "naudit/rule.h"
#include "naudit/violation.h"

#ifndef N00B_AUDIT_TEST_FIXTURE_DIR
#error "N00B_AUDIT_TEST_FIXTURE_DIR must be set by the build"
#endif

/*
 * Pre-WP-011 NULL fixture: per `test_naudit_engine.c`'s recorded
 * FIXTURE_NULL_FIRST_LINE, the fixture carries `NULL` in two
 * expression positions (lines 5 and 6). The standalone naudit
 * binary reports 2 violations; that's the value the smoke test
 * was instructed to MEASURE before asserting.
 */

static n00b_string_t *
fixture_path(const char *fname)
{
    char buf[1024];
    int  n = snprintf(buf, sizeof(buf), "%s/%s",
                      N00B_AUDIT_TEST_FIXTURE_DIR, fname);
    assert(n > 0 && (size_t)n < sizeof(buf));
    return n00b_string_from_cstr(buf);
}

static void
remove_tree(const char *path)
{
    /* Best-effort recursive remove for the test workspace. */
    char cmd[2048];
    int  n = snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (n <= 0 || (size_t)n >= sizeof(cmd)) {
        return;
    }
    (void)system(cmd);
}

static void
write_file(n00b_string_t *path, const char *body)
{
    FILE *fh = fopen(path->data, "w");
    assert(fh != nullptr);
    fputs(body, fh);
    fclose(fh);
}

/*
 * Set up a private project root with:
 *   <root>/audit-rules.bnf  — the canonical NULL rule (so
 *      `content_hash` is computed deterministically).
 *   <root>/fixture_null.c   — copy of the in-tree fixture so
 *      regions match.
 *
 * Returns the root path as an absolute n00b_string_t.
 */
static n00b_string_t *
make_project_root(const char *suffix)
{
    char buf[1024];
    int  n = snprintf(buf, sizeof(buf), "%s/tmp_baseline_%s",
                      N00B_AUDIT_TEST_FIXTURE_DIR, suffix);
    assert(n > 0 && (size_t)n < sizeof(buf));
    remove_tree(buf);
    if (mkdir(buf, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir(%s) failed: %s\n", buf, strerror(errno));
        assert(false);
    }
    n00b_string_t *root = n00b_string_from_cstr(buf);

    /* Write audit-rules.bnf — the canonical NULL rule from
     * audit-rules.bnf, isolated to the minimal NULL-only form so the
     * violation count is deterministic. WP-016: the rule queries the
     * existing `<provided_identifier>` NT and narrows to `NULL` via the
     * `is_null_keyword` text-predicate filter (no synthetic grafted NT
     * — see engine.c get_or_load_grammar / DECISIONS D-033). */
    n00b_string_t *rules_path = fixture_path("../../audit-rules.bnf");
    (void)rules_path;
    char rules_target[1280];
    snprintf(rules_target, sizeof(rules_target), "%s/audit-rules.bnf", buf);
    n00b_string_t *target = n00b_string_from_cstr(rules_target);
    write_file(target,
               "@schema_version 1\n"
               "@project test_baseline\n"
               "@description WP-011 baseline test workspace.\n"
               "@source_doc test/fixtures/naudit/test_naudit_baseline.c\n"
               "@dependencies\n"
               "@extensions\n"
               "    c: .c, .h\n"
               "\n"
               "@filter_def is_null_keyword\n"
               "    expr: arg.text_equals(\"NULL\")\n"
               "    description: Matches the literal identifier `NULL`.\n"
               "\n"
               "@rule n00b.s2_1.null\n"
               "@title NULL -> nullptr\n"
               "@section section 2.1\n"
               "@language c\n"
               "@violation_nt provided_identifier\n"
               "@filter is_null_keyword\n"
               "@rationale C23 has nullptr.\n"
               "@bad int *p = NULL;\n"
               "@good int *p = nullptr;\n"
               "@guidance Replace NULL with nullptr.\n");

    /* Copy fixture_null.c verbatim. */
    char fixture_target[1280];
    snprintf(fixture_target, sizeof(fixture_target),
             "%s/fixture_null.c", buf);
    n00b_string_t *fixture_dst = n00b_string_from_cstr(fixture_target);
    write_file(fixture_dst,
               "/* WP-011 baseline-test fixture (copy of fixture_null.c). */\n"
               "int\n"
               "main(void)\n"
               "{\n"
               "    int *p = NULL;\n"
               "    return p == NULL ? 0 : 1;\n"
               "}\n");

    return root;
}

static n00b_audit_guidance_t *
load_root_guidance(n00b_string_t *root)
{
    char buf[1280];
    snprintf(buf, sizeof(buf), "%s/audit-rules.bnf", root->data);
    n00b_string_t *p = n00b_string_from_cstr(buf);
    auto r = n00b_audit_load_guidance(p);
    if (n00b_result_is_err(r)) {
        fprintf(stderr,
                "load guidance failed: %.*s\n",
                (int)n00b_audit_err_str(n00b_result_get_err(r))->u8_bytes,
                n00b_audit_err_str(n00b_result_get_err(r))->data);
    }
    assert(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_list_t(n00b_audit_violation_t *) *
audit_fixture(n00b_audit_guidance_t *g, n00b_string_t *root,
              bool ignore_baseline)
{
    auto er = n00b_audit_engine_new(g);
    assert(n00b_result_is_ok(er));
    n00b_audit_engine_t *engine = n00b_result_get(er);
    n00b_audit_engine_set_ignore_baseline(engine, ignore_baseline);
    /*
     * WP-012: the baseline test workspace ships no roster and no
     * signed exemption files (the test pre-dates the signature
     * gate). Set `allow_unsigned` so the gate downgrades the
     * missing-signature verdict to a warning + keep — which is
     * the WP-011 behavior the test was written against.
     */
    n00b_audit_engine_set_allow_unsigned(engine, true);

    char buf[1280];
    snprintf(buf, sizeof(buf), "%s/fixture_null.c", root->data);
    n00b_string_t *p = n00b_string_from_cstr(buf);

    auto cr = n00b_audit_engine_check_file(engine, p);
    assert(n00b_result_is_ok(cr));
    return n00b_result_get(cr);
}

/* ---------------------------------------------------------------- */
/* Test 1 — hand-crafted exemption suppresses the violation         */
/* ---------------------------------------------------------------- */

static void
test_exemption_suppresses(void)
{
    n00b_string_t *root = make_project_root("exemption");

    /* Step A: run once, capture hash + fingerprint of the
     * violations. */
    n00b_audit_guidance_t *g_pre = load_root_guidance(root);
    n00b_list_t(n00b_audit_violation_t *) *vs_pre =
        audit_fixture(g_pre, root, false);
    int64_t n_pre = n00b_list_len(*vs_pre);
    assert(n_pre >= 1);
    n00b_audit_violation_t *first = n00b_list_get(*vs_pre, 0);
    assert(first != nullptr);
    assert(first->rule != nullptr);
    assert(first->rule->content_hash != nullptr);
    assert(first->region_fingerprint != nullptr);
    printf("  measured pre-suppression count = %lld (hash=%.*s, fp=%.*s)\n",
           (long long)n_pre,
           (int)first->rule->content_hash->u8_bytes,
           first->rule->content_hash->data,
           (int)first->region_fingerprint->u8_bytes,
           first->region_fingerprint->data);

    /* Step B: write an exemption file under audit/exemptions/. */
    char ex_dir[1280];
    snprintf(ex_dir, sizeof(ex_dir), "%s/audit", root->data);
    mkdir(ex_dir, 0755);
    snprintf(ex_dir, sizeof(ex_dir), "%s/audit/exemptions", root->data);
    mkdir(ex_dir, 0755);
    char ex_path[1408];
    snprintf(ex_path, sizeof(ex_path), "%s/null.bnf", ex_dir);
    n00b_string_t *path = n00b_string_from_cstr(ex_path);
    FILE *fh = fopen(path->data, "w");
    assert(fh != nullptr);
    fprintf(fh, "@schema_version 1\n\n");
    fprintf(fh, "@exemption suppress_null_0001\n");
    fprintf(fh, "@version 1\n");
    fprintf(fh, "@rule_id %.*s\n",
            (int)first->rule->content_hash->u8_bytes,
            first->rule->content_hash->data);
    fprintf(fh, "@rule_name %.*s\n",
            (int)first->rule->id->u8_bytes,
            first->rule->id->data);
    fprintf(fh, "@region_fingerprint %.*s\n",
            (int)first->region_fingerprint->u8_bytes,
            first->region_fingerprint->data);
    fprintf(fh, "@rationale test-only exemption\n");
    fprintf(fh, "@signer_id placeholder\n");
    fclose(fh);

    /* Step C: re-load guidance and re-audit; expect zero. */
    n00b_audit_guidance_t *g_post = load_root_guidance(root);
    assert(g_post->exemptions != nullptr);
    assert(n00b_list_len(*g_post->exemptions) >= 1);
    n00b_list_t(n00b_audit_violation_t *) *vs_post =
        audit_fixture(g_post, root, false);
    int64_t n_post = n00b_list_len(*vs_post);
    printf("  post-suppression count = %lld\n", (long long)n_post);
    assert(n_post == 0);
    printf("  [PASS] exemption_suppresses (N=%lld -> 0)\n",
           (long long)n_pre);

    remove_tree(root->data);
}

/* ---------------------------------------------------------------- */
/* Test 2 — baseline finalize + re-audit + --ignore-baseline        */
/* ---------------------------------------------------------------- */

static void
test_baseline_workflow(void)
{
    n00b_string_t *root = make_project_root("baseline");

    /* Pre-measure violations. */
    n00b_audit_guidance_t *g_pre = load_root_guidance(root);
    n00b_list_t(n00b_audit_violation_t *) *vs_pre =
        audit_fixture(g_pre, root, false);
    int64_t n_pre = n00b_list_len(*vs_pre);
    assert(n_pre >= 1);
    printf("  measured baseline-pre count N=%lld\n", (long long)n_pre);

    /* Finalize: write baseline.bnf. */
    auto bfr = n00b_audit_finalize_baseline(root, vs_pre, false);
    assert(n00b_result_is_ok(bfr));
    int written = n00b_result_get(bfr);
    assert(written == (int)n_pre);
    printf("  finalize wrote %d entries\n", written);

    /* Re-finalize without --overwrite should refuse. */
    auto bfr2 = n00b_audit_finalize_baseline(root, vs_pre, false);
    assert(n00b_result_is_err(bfr2));
    printf("  [PASS] second finalize refused without overwrite\n");

    /* With --overwrite, should succeed again. */
    auto bfr3 = n00b_audit_finalize_baseline(root, vs_pre, true);
    assert(n00b_result_is_ok(bfr3));

    /* Re-load guidance → guidance->baseline now populated. */
    n00b_audit_guidance_t *g_post = load_root_guidance(root);
    assert(g_post->baseline != nullptr);
    assert(n00b_list_len(*g_post->baseline) == (int64_t)n_pre);

    /* Re-audit honoring the baseline → zero. */
    n00b_list_t(n00b_audit_violation_t *) *vs_clean =
        audit_fixture(g_post, root, false);
    int64_t n_clean = n00b_list_len(*vs_clean);
    printf("  baselined re-audit -> %lld violations\n",
           (long long)n_clean);
    assert(n_clean == 0);

    /* Re-audit with --ignore-baseline → N. */
    n00b_list_t(n00b_audit_violation_t *) *vs_ignore =
        audit_fixture(g_post, root, true);
    int64_t n_ignore = n00b_list_len(*vs_ignore);
    printf("  --ignore-baseline re-audit -> %lld violations\n",
           (long long)n_ignore);
    assert(n_ignore == n_pre);
    printf("  [PASS] baseline_workflow (N=%lld -> 0 baselined, N restored)\n",
           (long long)n_pre);

    remove_tree(root->data);
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    test_exemption_suppresses();
    test_baseline_workflow();

    printf("All naudit baseline WP-011 integration checks passed.\n");
    return 0;
}

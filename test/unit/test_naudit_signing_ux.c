/*
 * WP-014 Phase 1 — unit tests for the interactive signing UX.
 *
 * Coverage (per the WP-014 preflight item 6):
 *
 *   1. Proposal discovery — write 3 `.bnf` files under a tmp
 *      `audit/exemptions/`; verify the discovery helper returns
 *      exactly the 3 paths (alphabetically sorted), and that a
 *      `.bnf` with a `.sig` sibling is excluded.
 *   2. Rationale-blank — write a draft with a known rationale; call
 *      the blanking helper; verify the field is empty (and
 *      idempotent on a second call).
 *   3. End-to-end sign one proposal — feed scripted input
 *      (rationale + expiration + approve) via a buffer-backed
 *      input source; verify the resulting record has the correct
 *      rationale, expires_at, and a valid `.sig`.
 *   4. Decline path — feed scripted input (decline); verify no
 *      `.sig` is written.
 *   5. `--initial-adoption` bulk-sign — three proposals; run the
 *      bulk-sign with a test signing key; verify all three have
 *      standardized rationales + 90-day expiry + valid sigs.
 *   6. Expiration enforcement — synthesize an expired exemption +
 *      a non-expired one; verify `n00b_audit_exemption_is_expired`
 *      agrees with our hand-coded date math.
 *
 * Bootstrap shape mirrors test_naudit_signing.c per the relaxed
 * test-file convention: libc `<assert.h>` + `<stdio.h>` etc. are
 * allowed for harness scaffolding.
 *
 * The buffer-backed input source (DF-BA resolution) is the key
 * enabler for these tests: scripted developer input becomes a
 * literal byte buffer, fed into the signing flow in-process. No
 * subprocess spawn, no pipe wiring.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "test_portability.h"

#include "n00b.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "text/strings/string_ops.h"

#include "naudit/naudit.h"
#include "naudit/errors.h"
#include "naudit/exemption.h"
#include "naudit/guidance.h"
#include "naudit/rule.h"
#include "naudit/signing_ux.h"
#include "naudit/violation.h"

#ifndef N00B_AUDIT_TEST_FIXTURE_DIR
#error "N00B_AUDIT_TEST_FIXTURE_DIR must be set by the build"
#endif

/* ---------------------------------------------------------------- */
/* Tiny POSIX helpers (test-relaxed I/O)                            */
/* ---------------------------------------------------------------- */

static void
remove_tree(const char *path)
{
    char cmd[2048];
    int  n = snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (n <= 0 || (size_t)n >= sizeof(cmd)) {
        return;
    }
    (void)system(cmd);
}

static void
make_dir(const char *p)
{
    int rc = mkdir(p, 0755);
    if (rc != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir(%s) failed: %s\n", p, strerror(errno));
        assert(false);
    }
}

static void
write_text(const char *path, const char *body)
{
    FILE *fh = fopen(path, "w");
    assert(fh != nullptr);
    fputs(body, fh);
    fclose(fh);
}

static int
file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 ? 1 : 0;
}

static void
gen_keypair(const char *root, const char *base)
{
    char out[2048];
    snprintf(out, sizeof(out), "%s/%s", root, base);
    char rmcmd[2200];
    snprintf(rmcmd, sizeof(rmcmd), "rm -f '%s' '%s.pub'", out, out);
    (void)system(rmcmd);
    char cmd[4096];
    int  n = snprintf(cmd, sizeof(cmd),
                      "ssh-keygen -q -t ed25519 -f '%s' -N '' >/dev/null 2>&1",
                      out);
    assert(n > 0 && (size_t)n < sizeof(cmd));
    int rc = system(cmd);
    if (rc != 0) {
        fprintf(stderr,
                "ssh-keygen failed for %s (rc=%d) — is OpenSSH installed?\n",
                out, rc);
        assert(false);
    }
}

static char *
slurp(const char *path)
{
    FILE *fh = fopen(path, "r");
    assert(fh != nullptr);
    fseek(fh, 0, SEEK_END);
    long n = ftell(fh);
    fseek(fh, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)n + 1);
    assert(buf != nullptr);
    size_t got = fread(buf, 1, (size_t)n, fh);
    assert((long)got == n);
    buf[n] = '\0';
    fclose(fh);
    return buf;
}

static void
write_roster(const char *roster_path,
             const char *principal,
             const char *pub_path)
{
    char *pub = slurp(pub_path);
    char *nl  = strchr(pub, '\n');
    if (nl) {
        *nl = '\0';
    }
    int spaces = 0;
    char *p;
    for (p = pub; *p; p++) {
        if (*p == ' ') {
            spaces++;
        }
    }
    if (spaces >= 2) {
        char *last = strrchr(pub, ' ');
        if (last) {
            *last = '\0';
        }
    }
    FILE *fh = fopen(roster_path, "w");
    assert(fh != nullptr);
    fprintf(fh, "%s %s\n", principal, pub);
    fclose(fh);
    free(pub);
}

/*
 * Build a minimal proposal file at `<root>/audit/exemptions/<name>.bnf`.
 * Carries the fields the loader requires (version, rule_id,
 * region_fingerprint, rationale).
 */
static void
write_proposal(const char *root, const char *name,
               const char *rule_id, const char *fingerprint,
               const char *rationale)
{
    char path[2400];
    snprintf(path, sizeof(path), "%s/audit/exemptions/%s.bnf", root, name);
    FILE *fh = fopen(path, "w");
    assert(fh != nullptr);
    fprintf(fh,
            "@schema_version 1\n"
            "\n"
            "@exemption %s\n"
            "@version 1\n"
            "@rule_id %s\n"
            "@locator_line 5\n"
            "@locator_col 5\n"
            "@locator_end_line 5\n"
            "@locator_end_col 9\n"
            "@region_fingerprint %s\n"
            "@rationale %s\n",
            name, rule_id, fingerprint, rationale);
    fclose(fh);
}

/* ---------------------------------------------------------------- */
/* Shared workspace                                                  */
/* ---------------------------------------------------------------- */

static char workspace_root[2048];

static void
setup_workspace(const char *suffix)
{
    snprintf(workspace_root, sizeof(workspace_root),
             "%s/tmp_signing_ux_%s",
             N00B_AUDIT_TEST_FIXTURE_DIR, suffix);
    remove_tree(workspace_root);
    make_dir(workspace_root);
    char buf[2200];
    snprintf(buf, sizeof(buf), "%s/audit", workspace_root);
    make_dir(buf);
    snprintf(buf, sizeof(buf), "%s/audit/exemptions", workspace_root);
    make_dir(buf);
}

/* ---------------------------------------------------------------- */
/* Test 1 — proposal discovery                                      */
/* ---------------------------------------------------------------- */

static void
test_discover_proposals(void)
{
    setup_workspace("discover");
    /* Three proposals, no .sig siblings → all three discovered. */
    write_proposal(workspace_root, "alpha",
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                   "first");
    write_proposal(workspace_root, "beta",
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                   "cccccccccccccccccccccccccccccccc",
                   "second");
    write_proposal(workspace_root, "gamma",
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                   "dddddddddddddddddddddddddddddddd",
                   "third");

    n00b_string_t *root = n00b_string_from_cstr(workspace_root);
    auto rr = n00b_audit_discover_proposals(root);
    assert(n00b_result_is_ok(rr));
    n00b_list_t(n00b_string_t *) *list = n00b_result_get(rr);
    assert(list != nullptr);
    int64_t n = n00b_list_len(*list);
    printf("  discovered %lld proposals\n", (long long)n);
    assert(n == 3);

    /* Alphabetical order: alpha, beta, gamma. */
    n00b_string_t *p0 = n00b_list_get(*list, 0);
    n00b_string_t *p1 = n00b_list_get(*list, 1);
    n00b_string_t *p2 = n00b_list_get(*list, 2);
    assert(p0 && p1 && p2);
    assert(strstr(p0->data, "alpha.bnf") != nullptr);
    assert(strstr(p1->data, "beta.bnf") != nullptr);
    assert(strstr(p2->data, "gamma.bnf") != nullptr);

    /* Add a .sig sibling for beta → it should now be excluded. */
    char beta_sig[2400];
    snprintf(beta_sig, sizeof(beta_sig),
             "%s/audit/exemptions/beta.bnf.sig", workspace_root);
    write_text(beta_sig, "fake-sig-bytes\n");
    auto rr2 = n00b_audit_discover_proposals(root);
    assert(n00b_result_is_ok(rr2));
    n00b_list_t(n00b_string_t *) *list2 = n00b_result_get(rr2);
    int64_t m = n00b_list_len(*list2);
    printf("  after adding beta.sig: %lld proposals\n", (long long)m);
    assert(m == 2);

    printf("  [PASS] discover_proposals\n");
    remove_tree(workspace_root);
}

/* ---------------------------------------------------------------- */
/* Test 2 — rationale blank                                          */
/* ---------------------------------------------------------------- */

static void
test_blank_rationale(void)
{
    n00b_audit_exemption_t ex;
    ex.version            = 1;
    ex.rule_id            = nullptr;
    ex.rule_name          = nullptr;
    ex.file_path          = nullptr;
    ex.locator_line       = 0;
    ex.locator_col        = 0;
    ex.locator_end_line   = 0;
    ex.locator_end_col    = 0;
    ex.region_fingerprint = nullptr;
    ex.rationale          = n00b_string_from_cstr(
        "agent-authored rationale text");
    ex.signer_id          = nullptr;
    ex.approved_at        = nullptr;
    ex.expires_at         = nullptr;
    ex.source_file        = nullptr;
    assert(ex.rationale && ex.rationale->u8_bytes > 0);

    n00b_audit_exemption_blank_rationale(&ex);
    assert(ex.rationale != nullptr);
    assert(ex.rationale->u8_bytes == 0);

    /* Idempotent on a second call. */
    n00b_audit_exemption_blank_rationale(&ex);
    assert(ex.rationale != nullptr);
    assert(ex.rationale->u8_bytes == 0);
    printf("  [PASS] blank_rationale\n");
}

/* ---------------------------------------------------------------- */
/* Test 3 — end-to-end sign one proposal                            */
/* ---------------------------------------------------------------- */

static n00b_naudit_input_source_t *
script_input(const char *script)
{
    n00b_buffer_t *buf = n00b_buffer_from_bytes(
        (char *)script, (int64_t)strlen(script));
    return n00b_naudit_input_from_buffer(buf);
}

static void
test_sign_one_proposal(void)
{
    setup_workspace("sign_one");

    /* Generate key + roster. */
    gen_keypair(workspace_root, "id_one");
    char roster[2200];
    snprintf(roster, sizeof(roster), "%s/audit/allowed_signers",
             workspace_root);
    char pub[2200];
    snprintf(pub, sizeof(pub), "%s/id_one.pub", workspace_root);
    write_roster(roster, "alice@example.com", pub);

    write_proposal(workspace_root, "draft_one",
                   "1111111111111111111111111111aaaa",
                   "2222222222222222222222222222bbbb",
                   "agent-authored text that must be blanked");

    char proposal_path[2400];
    snprintf(proposal_path, sizeof(proposal_path),
             "%s/audit/exemptions/draft_one.bnf", workspace_root);

    char key_path[2200];
    snprintf(key_path, sizeof(key_path), "%s/id_one", workspace_root);

    n00b_string_t *p_str   = n00b_string_from_cstr(proposal_path);
    n00b_string_t *k_str   = n00b_string_from_cstr(key_path);
    n00b_string_t *sid_str = n00b_string_from_cstr("alice@example.com");

    /*
     * Script:
     *   - two lines of rationale + "." terminator
     *   - blank line for default expiration
     *   - "y" approve
     */
    const char *script =
        "vendor SDK shim is required until Q3.\n"
        "Replacement work tracked in JIRA-1234.\n"
        ".\n"
        "\n"
        "y\n";
    n00b_naudit_input_source_t *src = script_input(script);

    auto rr = n00b_audit_sign_proposal_interactive(
        p_str, k_str, sid_str, src, 365);
    if (n00b_result_is_err(rr)) {
        fprintf(stderr, "sign_one_proposal err code=%d\n",
                n00b_result_get_err(rr));
    }
    assert(n00b_result_is_ok(rr));
    int rc = n00b_result_get(rr);
    assert(rc == 0);

    /* .sig sibling must exist. */
    char sig_path[2400];
    snprintf(sig_path, sizeof(sig_path), "%s.sig", proposal_path);
    assert(file_exists(sig_path));

    /* Load it back and verify the rationale + expires_at landed. */
    auto lr = n00b_audit_load_exemptions(p_str);
    assert(n00b_result_is_ok(lr));
    n00b_list_t(n00b_audit_exemption_t *) *recs = n00b_result_get(lr);
    assert(n00b_list_len(*recs) >= 1);
    n00b_audit_exemption_t *ex = n00b_list_get(*recs, 0);
    assert(ex->rationale != nullptr);
    assert(ex->rationale->u8_bytes > 0);
    assert(strstr(ex->rationale->data, "vendor SDK shim") != nullptr);
    assert(strstr(ex->rationale->data, "JIRA-1234") != nullptr);
    /* Agent's original text must be gone. */
    assert(strstr(ex->rationale->data, "agent-authored") == nullptr);
    /* expires_at default = today + 365 days; verify the format and
     * that it's after today's date. */
    assert(ex->expires_at != nullptr);
    assert(ex->expires_at->u8_bytes == 10);
    n00b_string_t *today = n00b_audit_today_plus_days_iso(0);
    assert(n00b_audit_exemption_is_expired(ex, today) == false);

    printf("  [PASS] sign_one_proposal\n");
    remove_tree(workspace_root);
}

/* ---------------------------------------------------------------- */
/* Test 4 — decline path                                             */
/* ---------------------------------------------------------------- */

static void
test_decline_path(void)
{
    setup_workspace("decline");

    gen_keypair(workspace_root, "id_dec");
    char roster[2200];
    snprintf(roster, sizeof(roster), "%s/audit/allowed_signers",
             workspace_root);
    char pub[2200];
    snprintf(pub, sizeof(pub), "%s/id_dec.pub", workspace_root);
    write_roster(roster, "bob@example.com", pub);

    write_proposal(workspace_root, "draft_dec",
                   "ffffffffffffffffffffffffffffaaaa",
                   "eeeeeeeeeeeeeeeeeeeeeeeeeeeebbbb",
                   "agent rationale");

    char proposal_path[2400];
    snprintf(proposal_path, sizeof(proposal_path),
             "%s/audit/exemptions/draft_dec.bnf", workspace_root);
    char key_path[2200];
    snprintf(key_path, sizeof(key_path), "%s/id_dec", workspace_root);

    n00b_string_t *p_str   = n00b_string_from_cstr(proposal_path);
    n00b_string_t *k_str   = n00b_string_from_cstr(key_path);
    n00b_string_t *sid_str = n00b_string_from_cstr("bob@example.com");

    /* Script: rationale, expiration, then "n" for decline. */
    const char *script =
        "some rationale\n"
        ".\n"
        "\n"
        "n\n";
    n00b_naudit_input_source_t *src = script_input(script);

    auto rr = n00b_audit_sign_proposal_interactive(
        p_str, k_str, sid_str, src, 365);
    assert(n00b_result_is_ok(rr));
    int rc = n00b_result_get(rr);
    assert(rc == 1);  /* declined */

    /* No .sig should have been written. */
    char sig_path[2400];
    snprintf(sig_path, sizeof(sig_path), "%s.sig", proposal_path);
    assert(file_exists(sig_path) == 0);

    printf("  [PASS] decline_path\n");
    remove_tree(workspace_root);
}

/* ---------------------------------------------------------------- */
/* Test 5 — initial-adoption bulk-sign                              */
/* ---------------------------------------------------------------- */

static void
test_initial_adoption_bulk(void)
{
    setup_workspace("bulk");

    gen_keypair(workspace_root, "id_bulk");
    char roster[2200];
    snprintf(roster, sizeof(roster), "%s/audit/allowed_signers",
             workspace_root);
    char pub[2200];
    snprintf(pub, sizeof(pub), "%s/id_bulk.pub", workspace_root);
    write_roster(roster, "carol@example.com", pub);

    write_proposal(workspace_root, "draft_a",
                   "1111111111111111111111111111aaaa",
                   "2222222222222222222222222222bbbb",
                   "agent rationale a");
    write_proposal(workspace_root, "draft_b",
                   "1111111111111111111111111111aaaa",
                   "3333333333333333333333333333cccc",
                   "agent rationale b");
    write_proposal(workspace_root, "draft_c",
                   "1111111111111111111111111111aaaa",
                   "4444444444444444444444444444dddd",
                   "agent rationale c");

    char key_path[2200];
    snprintf(key_path, sizeof(key_path), "%s/id_bulk", workspace_root);
    n00b_string_t *root_str   = n00b_string_from_cstr(workspace_root);
    n00b_string_t *k_str      = n00b_string_from_cstr(key_path);
    n00b_string_t *sid_str    = n00b_string_from_cstr("carol@example.com");

    auto br = n00b_audit_sign_initial_adoption_bulk(
        root_str, k_str, sid_str, 90);
    if (n00b_result_is_err(br)) {
        fprintf(stderr, "bulk err code=%d\n", n00b_result_get_err(br));
    }
    assert(n00b_result_is_ok(br));
    int signed_count = n00b_result_get(br);
    printf("  bulk signed %d proposal(s)\n", signed_count);
    assert(signed_count == 3);

    /* All three .sig files exist. */
    const char *names[3] = {"draft_a", "draft_b", "draft_c"};
    for (int i = 0; i < 3; i++) {
        char sig_path[2400];
        snprintf(sig_path, sizeof(sig_path),
                 "%s/audit/exemptions/%s.bnf.sig",
                 workspace_root, names[i]);
        assert(file_exists(sig_path));
    }

    /* Inspect the first one's rationale + expiration. */
    char pp[2400];
    snprintf(pp, sizeof(pp), "%s/audit/exemptions/draft_a.bnf",
             workspace_root);
    auto lr = n00b_audit_load_exemptions(n00b_string_from_cstr(pp));
    assert(n00b_result_is_ok(lr));
    n00b_list_t(n00b_audit_exemption_t *) *recs = n00b_result_get(lr);
    n00b_audit_exemption_t *ex = n00b_list_get(*recs, 0);
    assert(ex->rationale != nullptr);
    assert(strstr(ex->rationale->data, "preexisting") != nullptr);
    assert(ex->expires_at != nullptr);
    assert(ex->expires_at->u8_bytes == 10);
    /* 90-day expiry → not expired today. */
    n00b_string_t *today = n00b_audit_today_plus_days_iso(0);
    assert(n00b_audit_exemption_is_expired(ex, today) == false);

    printf("  [PASS] initial_adoption_bulk\n");
    remove_tree(workspace_root);
}

/* ---------------------------------------------------------------- */
/* Test 6 — expiration enforcement                                  */
/* ---------------------------------------------------------------- */

static void
test_expiration_helper(void)
{
    n00b_audit_exemption_t ex;
    memset(&ex, 0, sizeof(ex));
    /* No expires_at → never expired. */
    ex.expires_at = nullptr;
    n00b_string_t *now = n00b_string_from_cstr("2026-05-28T12:00:00Z");
    assert(n00b_audit_exemption_is_expired(&ex, now) == false);

    ex.expires_at = n00b_string_empty();
    assert(n00b_audit_exemption_is_expired(&ex, now) == false);

    /* expires_at in the past (calendar form). */
    ex.expires_at = n00b_string_from_cstr("2025-01-01");
    assert(n00b_audit_exemption_is_expired(&ex, now) == true);

    /* expires_at in the future. */
    ex.expires_at = n00b_string_from_cstr("2099-12-31");
    assert(n00b_audit_exemption_is_expired(&ex, now) == false);

    /* Instant-form same-day past. */
    ex.expires_at = n00b_string_from_cstr("2026-05-28T11:59:59Z");
    assert(n00b_audit_exemption_is_expired(&ex, now) == true);

    /* Instant-form same-day future. */
    ex.expires_at = n00b_string_from_cstr("2026-05-28T12:00:01Z");
    assert(n00b_audit_exemption_is_expired(&ex, now) == false);

    printf("  [PASS] expiration_helper\n");
}

/* ---------------------------------------------------------------- */
/* Test 7 — expiration end-to-end through the match path            */
/* ---------------------------------------------------------------- */

/*
 * Exercises the wiring from `n00b_audit_exemption_match` into
 * `n00b_audit_exemption_is_expired`. The helper-only Test 6 above
 * does not catch wire breaks (e.g., if the expiration check were
 * accidentally removed from match()'s prologue). This test
 * synthesizes a matching (rule_id, fingerprint) pair and toggles
 * `expires_at` to confirm:
 *   - expired exemption  → match returns false (does NOT suppress)
 *   - future exemption   → match returns true  (suppresses)
 *   - no expires_at      → match returns true  (suppresses)
 *
 * Uses repo_root=nullptr to take the pure-fingerprint fallback
 * path (the pre-commit case), which keeps the test free of any
 * libgit2 / VCS dependencies while still routing through the same
 * expiration gate at the top of match().
 */
static void
test_expiration_end_to_end(void)
{
    /*
     * Build a synthetic rule with a content_hash. We only need the
     * content_hash field set; the matcher reads no other rule fields
     * on the fingerprint-fallback path.
     */
    n00b_audit_rule_t *rule = n00b_alloc(n00b_audit_rule_t);
    memset(rule, 0, sizeof(*rule));
    rule->content_hash = n00b_string_from_cstr(
        "deadbeefcafef00d0000000000000000");

    /* Violation referencing that rule, with a known fingerprint. */
    n00b_audit_violation_t *v = n00b_alloc(n00b_audit_violation_t);
    memset(v, 0, sizeof(*v));
    v->rule = rule;
    v->file = n00b_string_from_cstr("/tmp/n00b-audit-fake.c");
    v->line = 1;
    v->column = 1;
    v->end_line = 1;
    v->end_column = 5;
    v->region_fingerprint = n00b_string_from_cstr(
        "feedfacefeedfacefeedfacefeedface");

    /* Exemption that matches on rule_id + fingerprint. */
    n00b_audit_exemption_t ex;
    memset(&ex, 0, sizeof(ex));
    ex.rule_id            = rule->content_hash;
    ex.region_fingerprint = v->region_fingerprint;
    ex.source_file        = nullptr;  /* force fingerprint fallback */

    /* No expiration → suppresses. */
    ex.expires_at = nullptr;
    assert(n00b_audit_exemption_match(&ex, v, nullptr, 0) == true);

    /* Future expiration (~100 years out) → suppresses. */
    ex.expires_at = n00b_string_from_cstr("2125-01-01");
    assert(n00b_audit_exemption_match(&ex, v, nullptr, 0) == true);

    /* Past expiration → does NOT suppress (finding re-fires). */
    ex.expires_at = n00b_audit_today_plus_days_iso(-1);
    assert(ex.expires_at != nullptr);
    assert(ex.expires_at->u8_bytes == 10);
    assert(n00b_audit_exemption_match(&ex, v, nullptr, 0) == false);

    /*
     * Sanity: with the past expiration removed, the same exemption
     * suppresses again. Confirms the only thing that changed
     * suppression behavior was `expires_at`, not test bookkeeping.
     */
    ex.expires_at = nullptr;
    assert(n00b_audit_exemption_match(&ex, v, nullptr, 0) == true);

    printf("  [PASS] expiration_end_to_end\n");
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    test_discover_proposals();
    test_blank_rationale();
    test_sign_one_proposal();
    test_decline_path();
    test_initial_adoption_bulk();
    test_expiration_helper();
    test_expiration_end_to_end();

    printf("All naudit WP-014 signing-UX unit checks passed.\n");
    return 0;
}

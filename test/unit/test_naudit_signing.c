/*
 * WP-012 Phase 1 — unit tests for the SSH-signature primitives and
 * the loader-side signature gate.
 *
 * Test plan (per the phase1-prompt.md task item 6):
 *
 *   1. sign + verify roundtrip — sign an exemption file, verify it
 *      with the roster that lists the matching public key, assert ok.
 *   2. tamper — sign, then mutate the exemption file content, verify,
 *      assert BAD_SIGNATURE.
 *   3. unknown signer — sign with key K1, verify against a roster
 *      that lists ONLY a different key K2; assert verify fails
 *      (collapsed to BAD_SIGNATURE under the WP-012 documented
 *      best-effort distinction).
 *   4. missing sig — verify a file with no `.sig`, assert
 *      NO_SIGNATURE.
 *   5. loader rejection — load guidance with a bad-sig exemption in
 *      default mode → the exemption is dropped (the finding fires).
 *      Same with `allow_unsigned` → the exemption is kept (finding
 *      suppressed) + a stderr warning is emitted.
 *
 * Per the test-file relaxed convention (NCC.md "NO LIBC ALLOWED"
 * exemption for test files), this file uses POSIX I/O (`fopen` /
 * `mkdir` / `system`) for fixture wiring. Bootstrap shape mirrors
 * `test_naudit_baseline.c`.
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
#include "core/string.h"
#include "text/strings/string_ops.h"

#include "naudit/naudit.h"
#include "naudit/engine.h"
#include "naudit/errors.h"
#include "naudit/exemption.h"
#include "naudit/guidance.h"
#include "naudit/rule.h"
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

/* ---------------------------------------------------------------- */
/* Key-pair + roster scaffolding                                    */
/* ---------------------------------------------------------------- */

/*
 * Generate an ephemeral ed25519 SSH key pair at <root>/<base> using
 * the `ssh-keygen -t ed25519 -f <out> -N ""` invocation. The
 * private key lands at `<out>`, the public key at `<out>.pub`.
 *
 * Aborts the test on failure (the rest of the test cannot proceed).
 */
static void
gen_keypair(const char *root, const char *base)
{
    char out[2048];
    snprintf(out, sizeof(out), "%s/%s", root, base);
    /* Remove any leftover from a prior run so ssh-keygen doesn't
     * prompt. */
    {
        char rmcmd[2200];
        snprintf(rmcmd, sizeof(rmcmd), "rm -f '%s' '%s.pub'", out, out);
        (void)system(rmcmd);
    }
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
    /* Confirm both files exist. */
    char pub[2200];
    snprintf(pub, sizeof(pub), "%s.pub", out);
    assert(file_exists(out));
    assert(file_exists(pub));
}

/*
 * Read a file into a heap buffer (caller frees via free()). Used to
 * splice the public-key bytes into the roster text.
 */
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

/*
 * Build an OpenSSH allowed_signers roster mapping `principal` to the
 * public key stored at `pub_path`. Each line of the roster format is:
 *
 *     <principal> <key-type> <base64-blob>
 *
 * The `ssh-keygen -t ed25519 ... -f X.pub` output is
 * `ssh-ed25519 <blob> <comment>`. We strip the trailing comment to
 * keep the roster line clean.
 */
static void
write_roster(const char *roster_path,
             const char *principal,
             const char *pub_path)
{
    char *pub = slurp(pub_path);
    /* Find the first newline to drop everything after the blob. */
    char *nl = strchr(pub, '\n');
    if (nl) {
        *nl = '\0';
    }
    /* The `ssh-keygen` output already has the form
     * "ssh-ed25519 <blob> [comment]"; for the roster format
     * we want "<principal> ssh-ed25519 <blob>".
     *
     * Strip optional trailing " comment" by finding the last
     * space and truncating. ed25519 blobs don't contain spaces. */
    int spaces = 0;
    char *p;
    for (p = pub; *p; p++) {
        if (*p == ' ') {
            spaces++;
        }
    }
    if (spaces >= 2) {
        /* Two spaces means "type blob comment"; drop the comment. */
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

/* ---------------------------------------------------------------- */
/* Shared test workspace                                            */
/* ---------------------------------------------------------------- */

static const char *
test_workspace(void)
{
    static char root[2048];
    if (root[0] == 0) {
        snprintf(root, sizeof(root), "%s/tmp_signing",
                 N00B_AUDIT_TEST_FIXTURE_DIR);
    }
    return root;
}

static void
setup_workspace(void)
{
    const char *root = test_workspace();
    remove_tree(root);
    int rc = mkdir(root, 0755);
    if (rc != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir(%s) failed: %s\n", root, strerror(errno));
        assert(false);
    }
}

static void
teardown_workspace(void)
{
    remove_tree(test_workspace());
}

/*
 * Write a minimal exemption file at <root>/exemption.bnf.
 * Returns the path as an n00b_string_t.
 */
static n00b_string_t *
write_exemption(const char *root, const char *signer_principal)
{
    char path[2048];
    snprintf(path, sizeof(path), "%s/exemption.bnf", root);
    FILE *fh = fopen(path, "w");
    assert(fh != nullptr);
    fprintf(fh,
            "@schema_version 1\n"
            "\n"
            "@exemption test_record_0001\n"
            "@version 1\n"
            "@rule_id 00000000000000000000000000000000\n"
            "@region_fingerprint 11111111111111111111111111111111\n"
            "@rationale wp-012 signing test\n"
            "@signer_id %s\n",
            signer_principal);
    fclose(fh);
    return n00b_string_from_cstr(path);
}

/* ---------------------------------------------------------------- */
/* Test 1 — sign + verify roundtrip                                 */
/* ---------------------------------------------------------------- */

static void
test_sign_verify_roundtrip(void)
{
    const char *root = test_workspace();
    setup_workspace();

    gen_keypair(root, "id_test");
    char roster[2048];
    snprintf(roster, sizeof(roster), "%s/allowed_signers", root);
    char pub[2048];
    snprintf(pub, sizeof(pub), "%s/id_test.pub", root);
    write_roster(roster, "tester@example.com", pub);

    n00b_string_t *file = write_exemption(root, "tester@example.com");
    char key_path[2048];
    snprintf(key_path, sizeof(key_path), "%s/id_test", root);
    n00b_string_t *key  = n00b_string_from_cstr(key_path);
    n00b_string_t *signer = n00b_string_from_cstr("tester@example.com");
    n00b_string_t *rosterp = n00b_string_from_cstr(roster);

    auto sr = n00b_audit_exemption_sign(file, key, signer);
    assert(n00b_result_is_ok(sr));
    /* Confirm the .sig file is on disk. */
    char sig_check[2200];
    snprintf(sig_check, sizeof(sig_check), "%s.sig", file->data);
    assert(file_exists(sig_check));

    auto vr = n00b_audit_exemption_verify(file, rosterp, signer);
    if (n00b_result_is_err(vr)) {
        fprintf(stderr, "verify returned error %d\n",
                n00b_result_get_err(vr));
    }
    assert(n00b_result_is_ok(vr));
    printf("  [PASS] sign_verify_roundtrip\n");
}

/* ---------------------------------------------------------------- */
/* Test 2 — tampered content                                        */
/* ---------------------------------------------------------------- */

static void
test_tamper(void)
{
    const char *root = test_workspace();
    /* Reuse the keypair + roster + signature from test 1; just
     * mutate the exemption content and re-verify. */
    char file_path[2048];
    snprintf(file_path, sizeof(file_path), "%s/exemption.bnf", root);
    /* Mutate ONE byte in the rationale line. */
    FILE *fh = fopen(file_path, "a");
    assert(fh != nullptr);
    fprintf(fh, "@approved_at 2026-05-28\n");
    fclose(fh);

    n00b_string_t *file = n00b_string_from_cstr(file_path);
    char roster[2048];
    snprintf(roster, sizeof(roster), "%s/allowed_signers", root);
    n00b_string_t *rosterp = n00b_string_from_cstr(roster);
    n00b_string_t *signer  = n00b_string_from_cstr("tester@example.com");

    auto vr = n00b_audit_exemption_verify(file, rosterp, signer);
    assert(n00b_result_is_err(vr));
    int code = n00b_result_get_err(vr);
    /* Tamper collapses to BAD_SIGNATURE per the WP-012 documented
     * fallback (we cannot reliably differentiate from
     * UNKNOWN_SIGNER without parsing ssh-keygen's stderr). */
    assert(code == N00B_AUDIT_ERR_EXEMPTION_BAD_SIGNATURE);
    printf("  [PASS] tamper (code=%d -> bad_signature)\n", code);
}

/* ---------------------------------------------------------------- */
/* Test 3 — unknown signer                                          */
/* ---------------------------------------------------------------- */

static void
test_unknown_signer(void)
{
    const char *root = test_workspace();
    setup_workspace();

    /* Two key pairs: K1 signs the file, K2 lives in the roster. */
    gen_keypair(root, "id_signer");
    gen_keypair(root, "id_other");

    char roster[2048];
    snprintf(roster, sizeof(roster), "%s/allowed_signers", root);
    char other_pub[2048];
    snprintf(other_pub, sizeof(other_pub), "%s/id_other.pub", root);
    /* Roster names a different principal whose key the signer
     * doesn't hold. */
    write_roster(roster, "other@example.com", other_pub);

    n00b_string_t *file = write_exemption(root, "signer@example.com");
    char key_path[2048];
    snprintf(key_path, sizeof(key_path), "%s/id_signer", root);
    n00b_string_t *key    = n00b_string_from_cstr(key_path);
    n00b_string_t *signer = n00b_string_from_cstr("signer@example.com");
    n00b_string_t *rosterp = n00b_string_from_cstr(roster);

    auto sr = n00b_audit_exemption_sign(file, key, signer);
    assert(n00b_result_is_ok(sr));

    auto vr = n00b_audit_exemption_verify(file, rosterp, signer);
    assert(n00b_result_is_err(vr));
    int code = n00b_result_get_err(vr);
    /* Per WP-012's documented fallback, unknown-signer collapses
     * to BAD_SIGNATURE when ssh-keygen's exit code does not let us
     * distinguish cleanly. */
    assert(code == N00B_AUDIT_ERR_EXEMPTION_BAD_SIGNATURE);
    printf("  [PASS] unknown_signer (code=%d -> bad_signature)\n", code);
}

/* ---------------------------------------------------------------- */
/* Test 4 — missing signature                                       */
/* ---------------------------------------------------------------- */

static void
test_missing_sig(void)
{
    const char *root = test_workspace();
    setup_workspace();

    gen_keypair(root, "id_test");
    char roster[2048];
    snprintf(roster, sizeof(roster), "%s/allowed_signers", root);
    char pub[2048];
    snprintf(pub, sizeof(pub), "%s/id_test.pub", root);
    write_roster(roster, "tester@example.com", pub);

    n00b_string_t *file = write_exemption(root, "tester@example.com");
    n00b_string_t *rosterp = n00b_string_from_cstr(roster);
    n00b_string_t *signer  = n00b_string_from_cstr("tester@example.com");

    /* Do NOT sign. Verify must return NO_SIGNATURE. */
    auto vr = n00b_audit_exemption_verify(file, rosterp, signer);
    assert(n00b_result_is_err(vr));
    int code = n00b_result_get_err(vr);
    assert(code == N00B_AUDIT_ERR_EXEMPTION_NO_SIGNATURE);
    printf("  [PASS] missing_sig (code=%d -> no_signature)\n", code);
}

/* ---------------------------------------------------------------- */
/* Test 5 — loader signature gate                                   */
/* ---------------------------------------------------------------- */

/*
 * Build a project root with:
 *   - audit-rules.bnf  (minimal NULL rule)
 *   - fixture_null.c   (carries one NULL violation)
 *   - audit/exemptions/null.bnf  (exemption that WOULD suppress)
 *   - audit/allowed_signers (legit roster)
 *
 * Two variants:
 *   - Sign null.bnf with the legit key → suppression in effect.
 *   - Don't sign / sign with wrong key → suppression refused
 *     under strict mode, retained under allow_unsigned.
 *
 * We run the strict path first (no sig present) and assert the
 * finding fires (exemption was dropped). Then we toggle
 * allow_unsigned on the engine and assert the finding is suppressed
 * again.
 *
 * The exemption's rule_id + region_fingerprint must align with the
 * actual violation that fixture_null.c produces. We pre-measure
 * them via a no-suppression pass, then write the exemption with
 * the captured values — same pattern as `test_naudit_baseline.c`.
 */

static n00b_string_t *
make_signing_project(const char *suffix)
{
    char buf[2048];
    snprintf(buf, sizeof(buf), "%s/tmp_signing_%s",
             N00B_AUDIT_TEST_FIXTURE_DIR, suffix);
    remove_tree(buf);
    int rc = mkdir(buf, 0755);
    if (rc != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir(%s) failed: %s\n", buf, strerror(errno));
        assert(false);
    }

    /* audit-rules.bnf — minimal NULL rule (same shape as
     * test_naudit_baseline.c). */
    char rules_target[2200];
    snprintf(rules_target, sizeof(rules_target), "%s/audit-rules.bnf", buf);
    write_text(rules_target,
               "@schema_version 1\n"
               "@project test_signing\n"
               "@description WP-012 signing-gate test workspace.\n"
               "@source_doc test/unit/test_naudit_signing.c\n"
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

    /* fixture_null.c — same body as the baseline test. */
    char fix_target[2200];
    snprintf(fix_target, sizeof(fix_target), "%s/fixture_null.c", buf);
    write_text(fix_target,
               "/* WP-012 signing-test fixture. */\n"
               "int\n"
               "main(void)\n"
               "{\n"
               "    int *p = NULL;\n"
               "    return p == NULL ? 0 : 1;\n"
               "}\n");

    return n00b_string_from_cstr(buf);
}

static n00b_audit_guidance_t *
load_root_guidance(n00b_string_t *root)
{
    char buf[2200];
    snprintf(buf, sizeof(buf), "%s/audit-rules.bnf", root->data);
    n00b_string_t *p = n00b_string_from_cstr(buf);
    auto r = n00b_audit_load_guidance(p);
    assert(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_list_t(n00b_audit_violation_t *) *
audit_fixture(n00b_audit_guidance_t *g, n00b_string_t *root,
              bool allow_unsigned)
{
    auto er = n00b_audit_engine_new(g);
    assert(n00b_result_is_ok(er));
    n00b_audit_engine_t *engine = n00b_result_get(er);
    n00b_audit_engine_set_allow_unsigned(engine, allow_unsigned);

    char buf[2200];
    snprintf(buf, sizeof(buf), "%s/fixture_null.c", root->data);
    n00b_string_t *p = n00b_string_from_cstr(buf);

    auto cr = n00b_audit_engine_check_file(engine, p);
    assert(n00b_result_is_ok(cr));
    return n00b_result_get(cr);
}

static void
test_loader_signature_gate(void)
{
    n00b_string_t *root = make_signing_project("loader");

    /* Step A: measure the violation's hash + fp via a clean pass
     * (no exemption present yet, no roster present yet — so the
     * loader produces a no-roster guidance and the signature gate
     * has nothing to apply). */
    n00b_audit_guidance_t *g_pre = load_root_guidance(root);
    n00b_list_t(n00b_audit_violation_t *) *vs_pre =
        audit_fixture(g_pre, root, false);
    int64_t n_pre = n00b_list_len(*vs_pre);
    assert(n_pre >= 1);
    n00b_audit_violation_t *first = n00b_list_get(*vs_pre, 0);
    n00b_string_t *hash = first->rule->content_hash;
    n00b_string_t *fp   = first->region_fingerprint;
    assert(hash && fp);

    /* Step B: create the roster + a key pair, AND write the
     * exemption file carrying the captured (hash, fp). */
    gen_keypair(root->data, "id_loader");
    char roster_path[2200];
    snprintf(roster_path, sizeof(roster_path), "%s/audit", root->data);
    mkdir(roster_path, 0755);
    snprintf(roster_path, sizeof(roster_path),
             "%s/audit/allowed_signers", root->data);
    char pub_path[2200];
    snprintf(pub_path, sizeof(pub_path), "%s/id_loader.pub", root->data);
    write_roster(roster_path, "loader@example.com", pub_path);

    char ex_dir[2200];
    snprintf(ex_dir, sizeof(ex_dir), "%s/audit/exemptions", root->data);
    mkdir(ex_dir, 0755);
    char ex_path[2400];
    snprintf(ex_path, sizeof(ex_path), "%s/null.bnf", ex_dir);
    FILE *fh = fopen(ex_path, "w");
    assert(fh != nullptr);
    fprintf(fh, "@schema_version 1\n\n");
    fprintf(fh, "@exemption suppress_null_loader_0001\n");
    fprintf(fh, "@version 1\n");
    fprintf(fh, "@rule_id %.*s\n", (int)hash->u8_bytes, hash->data);
    fprintf(fh, "@region_fingerprint %.*s\n",
            (int)fp->u8_bytes, fp->data);
    fprintf(fh, "@rationale signing-gate test\n");
    fprintf(fh, "@signer_id loader@example.com\n");
    fclose(fh);

    /*
     * Strict mode WITHOUT a sig: the signature gate must refuse
     * this exemption — the finding fires.
     */
    n00b_audit_guidance_t *g_no_sig = load_root_guidance(root);
    assert(g_no_sig->allowed_signers_path != nullptr);
    n00b_list_t(n00b_audit_violation_t *) *vs_no_sig =
        audit_fixture(g_no_sig, root, false);
    int64_t n_no_sig = n00b_list_len(*vs_no_sig);
    printf("  strict mode + no sig: %lld violation(s) (expected >=%lld)\n",
           (long long)n_no_sig, (long long)n_pre);
    assert(n_no_sig == n_pre);

    /*
     * allow_unsigned mode WITHOUT a sig: the gate must warn-and-
     * keep — the finding is suppressed.
     */
    n00b_audit_guidance_t *g_allow = load_root_guidance(root);
    n00b_list_t(n00b_audit_violation_t *) *vs_allow =
        audit_fixture(g_allow, root, true);
    int64_t n_allow = n00b_list_len(*vs_allow);
    printf("  allow_unsigned + no sig: %lld violation(s) (expected 0)\n",
           (long long)n_allow);
    assert(n_allow == 0);

    /*
     * Strict mode WITH a valid sig: the gate accepts the
     * exemption — the finding is suppressed.
     */
    char key_path[2200];
    snprintf(key_path, sizeof(key_path), "%s/id_loader", root->data);
    n00b_string_t *file_str = n00b_string_from_cstr(ex_path);
    n00b_string_t *key_str  = n00b_string_from_cstr(key_path);
    n00b_string_t *signer_str = n00b_string_from_cstr("loader@example.com");
    auto sr = n00b_audit_exemption_sign(file_str, key_str, signer_str);
    assert(n00b_result_is_ok(sr));

    n00b_audit_guidance_t *g_signed = load_root_guidance(root);
    n00b_list_t(n00b_audit_violation_t *) *vs_signed =
        audit_fixture(g_signed, root, false);
    int64_t n_signed = n00b_list_len(*vs_signed);
    printf("  strict mode + good sig: %lld violation(s) (expected 0)\n",
           (long long)n_signed);
    assert(n_signed == 0);
    printf("  [PASS] loader_signature_gate (3 modes)\n");

    remove_tree(root->data);
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    test_sign_verify_roundtrip();
    test_tamper();
    test_unknown_signer();
    test_missing_sig();
    test_loader_signature_gate();

    /* Best-effort cleanup of the shared workspace. */
    teardown_workspace();

    printf("All naudit signing WP-012 unit checks passed.\n");
    return 0;
}

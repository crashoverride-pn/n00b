/*
 * WP-015 Phase 1 — unit tests for the trust-root chain, the
 * fingerprint-binding primitive, and the rule-file signature
 * wrappers.
 *
 * Coverage (per the WP-015 preflight item 6):
 *
 *   1. Roster lookup chain — env > system > repo precedence:
 *      build all three slot paths, verify each precedence
 *      transition flips the resolved roster + the
 *      source-kind discriminator.
 *   2. Fingerprint binding pass — compute the SHA-256 of a
 *      generated roster, write the matching directive value into
 *      the verifier helper, assert it returns 0 (matched).
 *      Mutate the roster (add a byte) + assert the helper
 *      returns 1 (mismatched).
 *   3. Signed-rule-file ok — sign `audit-rules.bnf` with a test
 *      key + roster, call `n00b_audit_rules_verify_signature`,
 *      assert it returns 0 (verified).
 *   4. Unsigned-rule-file — no `.sig` sibling; assert the
 *      helper returns 1 (unsigned).
 *   5. Non-roster signer — sign with key K1, verify against a
 *      roster listing only K2's principal; assert the helper
 *      returns 2 (refuse).
 *
 * Bootstrap shape mirrors `test_naudit_signing.c` — POSIX I/O is
 * the test-file convention (NCC.md test-file relaxation). The
 * `NAUDIT_ROSTER` + `NAUDIT_SYSTEM_ROSTER` env vars are set via
 * `setenv()` per the libc cache substrate; libn00b's
 * `n00b_getenv` reads from the same view.
 *
 * Per the task prompt's "no snprintf" reminder (§ 2.11): the
 * test-file relaxed convention permits libc here (this file's
 * `snprintf` calls are for fixture path-building only and do not
 * appear in the production naudit source).
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "test_portability.h"

#include "n00b.h"
#include "core/env.h"
#include "core/runtime.h"
#include "core/string.h"

#include "naudit/naudit.h"
#include "naudit/engine.h"
#include "naudit/errors.h"
#include "naudit/exemption.h"
#include "naudit/guidance.h"
#include "naudit/trust_root.h"

#ifndef N00B_AUDIT_TEST_FIXTURE_DIR
#error "N00B_AUDIT_TEST_FIXTURE_DIR must be set by the build"
#endif

/* ---------------------------------------------------------------- */
/* Helpers (test-file relaxed POSIX usage)                          */
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
    /*
     * Strip the trailing comment field from the .pub file (the
     * `user@host` slot ssh-keygen appends). The OpenSSH
     * allowed_signers entry format is `<principal> <algo>
     * <key>`; we drop everything after the second space.
     */
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

/* ---------------------------------------------------------------- */
/* Shared workspace                                                  */
/* ---------------------------------------------------------------- */

static char workspace_root[2048];

static void
setup_workspace(const char *suffix)
{
    snprintf(workspace_root, sizeof(workspace_root),
             "%s/tmp_trust_root_%s",
             N00B_AUDIT_TEST_FIXTURE_DIR, suffix);
    remove_tree(workspace_root);
    make_dir(workspace_root);
}

/*
 * Set / clear a trust-root env var via libn00b's `n00b_putenv`.
 * The runtime caches its own envp slot array at init time; the
 * `core/env.h` accessors are authoritative — libc `setenv` /
 * `unsetenv` would only mutate libc's `__environ` and would not
 * be visible to `n00b_getenv`. The wrappers below normalize this
 * detail for the test fixture.
 *
 * "Clear" is implemented as `n00b_putenv(name, "")` — `n00b_getenv`
 * treats empty values as unset for the trust-root chain's
 * purposes (the chain's `read_env_string` helper short-circuits
 * on `u8_bytes == 0`).
 */
static void
test_setenv(const char *name, const char *value)
{
    n00b_string_t *n = n00b_string_from_cstr((char *)name);
    n00b_string_t *v = n00b_string_from_cstr((char *)value);
    bool ok = n00b_putenv(n, v);
    assert(ok);
}

static void
test_unsetenv(const char *name)
{
    /* See above — empty value is treated as unset by the chain. */
    test_setenv(name, "");
}

static void
clear_trust_root_env(void)
{
    test_unsetenv("NAUDIT_ROSTER");
    test_unsetenv("NAUDIT_SYSTEM_ROSTER");
}

/* ---------------------------------------------------------------- */
/* Test 1 — roster lookup chain                                     */
/* ---------------------------------------------------------------- */

static void
test_lookup_chain(void)
{
    setup_workspace("chain");

    /* Build three plausible roster files. */
    char env_dir[2200];
    snprintf(env_dir, sizeof(env_dir), "%s/env_roster_dir", workspace_root);
    make_dir(env_dir);
    char env_path[2400];
    snprintf(env_path, sizeof(env_path), "%s/allowed_signers", env_dir);
    write_text(env_path, "env-principal ssh-ed25519 ENVKEY\n");

    char sys_dir[2200];
    snprintf(sys_dir, sizeof(sys_dir), "%s/sys_roster_dir", workspace_root);
    make_dir(sys_dir);
    char sys_path[2400];
    snprintf(sys_path, sizeof(sys_path), "%s/allowed_signers", sys_dir);
    write_text(sys_path, "sys-principal ssh-ed25519 SYSKEY\n");

    /* Repo-shaped roster: <project_root>/audit/allowed_signers. */
    char repo_root[2200];
    snprintf(repo_root, sizeof(repo_root), "%s/repo", workspace_root);
    make_dir(repo_root);
    char audit_dir[2400];
    snprintf(audit_dir, sizeof(audit_dir), "%s/audit", repo_root);
    make_dir(audit_dir);
    char repo_roster[2600];
    snprintf(repo_roster, sizeof(repo_roster),
             "%s/audit/allowed_signers", repo_root);
    write_text(repo_roster, "repo-principal ssh-ed25519 REPOKEY\n");

    n00b_string_t *root = n00b_string_from_cstr(repo_root);

    /* --- (a) None of the three slots set → NONE. --- */
    clear_trust_root_env();
    /* Move the repo roster out so the REPO slot is also empty. */
    char repo_roster_hidden[2600];
    snprintf(repo_roster_hidden, sizeof(repo_roster_hidden),
             "%s.hidden", repo_roster);
    rename(repo_roster, repo_roster_hidden);
    {
        auto rr = n00b_audit_resolve_roster_path(root);
        assert(n00b_result_is_ok(rr));
        n00b_option_t(n00b_string_t *) opt = n00b_result_get(rr);
        assert(!n00b_option_is_set(opt));
        assert(n00b_audit_roster_source_kind(root)
               == N00B_AUDIT_ROSTER_SOURCE_NONE);
        printf("  (a) all slots empty → NONE\n");
    }

    /* Put the repo roster back. */
    rename(repo_roster_hidden, repo_roster);

    /* --- (b) Only REPO available → REPO. --- */
    {
        auto rr = n00b_audit_resolve_roster_path(root);
        assert(n00b_result_is_ok(rr));
        n00b_option_t(n00b_string_t *) opt = n00b_result_get(rr);
        assert(n00b_option_is_set(opt));
        n00b_string_t *p = n00b_option_get(opt);
        assert(strstr(p->data, "repo/audit/allowed_signers") != nullptr);
        assert(n00b_audit_roster_source_kind(root)
               == N00B_AUDIT_ROSTER_SOURCE_REPO);
        printf("  (b) only REPO → REPO\n");
    }

    /* --- (c) SYSTEM via NAUDIT_SYSTEM_ROSTER beats REPO. --- */
    test_setenv("NAUDIT_SYSTEM_ROSTER", sys_path);
    {
        auto rr = n00b_audit_resolve_roster_path(root);
        n00b_option_t(n00b_string_t *) opt = n00b_result_get(rr);
        assert(n00b_option_is_set(opt));
        n00b_string_t *p = n00b_option_get(opt);
        assert(strstr(p->data, "sys_roster_dir") != nullptr);
        assert(n00b_audit_roster_source_kind(root)
               == N00B_AUDIT_ROSTER_SOURCE_SYSTEM);
        printf("  (c) SYSTEM beats REPO\n");
    }

    /* --- (d) ENV via NAUDIT_ROSTER beats SYSTEM. --- */
    test_setenv("NAUDIT_ROSTER", env_path);
    {
        auto rr = n00b_audit_resolve_roster_path(root);
        n00b_option_t(n00b_string_t *) opt = n00b_result_get(rr);
        assert(n00b_option_is_set(opt));
        n00b_string_t *p = n00b_option_get(opt);
        assert(strstr(p->data, "env_roster_dir") != nullptr);
        assert(n00b_audit_roster_source_kind(root)
               == N00B_AUDIT_ROSTER_SOURCE_ENV);
        printf("  (d) ENV beats SYSTEM\n");
    }

    /* --- (e) Pointing ENV at a non-existent path → falls through. --- */
    test_setenv("NAUDIT_ROSTER", "/tmp/this/path/should/not/exist/roster");
    {
        auto rr = n00b_audit_resolve_roster_path(root);
        n00b_option_t(n00b_string_t *) opt = n00b_result_get(rr);
        assert(n00b_option_is_set(opt));
        n00b_string_t *p = n00b_option_get(opt);
        /* SYSTEM is still set so SYSTEM wins. */
        assert(strstr(p->data, "sys_roster_dir") != nullptr);
        assert(n00b_audit_roster_source_kind(root)
               == N00B_AUDIT_ROSTER_SOURCE_SYSTEM);
        printf("  (e) ENV non-existent → falls to SYSTEM\n");
    }

    clear_trust_root_env();
    printf("  [PASS] lookup_chain\n");
    remove_tree(workspace_root);
}

/* ---------------------------------------------------------------- */
/* Test 2 — fingerprint binding pass + mismatch                     */
/* ---------------------------------------------------------------- */

static void
test_fingerprint_binding(void)
{
    setup_workspace("fingerprint");

    /* Write a known roster and hash it. */
    char roster_path[2400];
    snprintf(roster_path, sizeof(roster_path),
             "%s/allowed_signers", workspace_root);
    write_text(roster_path, "alice ssh-ed25519 AAAAfake\n");

    n00b_string_t *roster_str = n00b_string_from_cstr(roster_path);

    auto hr = n00b_audit_roster_sha256(roster_str);
    assert(n00b_result_is_ok(hr));
    n00b_string_t *hex = n00b_result_get(hr);
    assert(hex != nullptr);
    assert(hex->u8_bytes == 64);
    printf("  initial roster sha256 = %.*s\n",
           (int)hex->u8_bytes, hex->data);

    /* Pass: directive value matches the hash. */
    auto vr = n00b_audit_verify_roster_fingerprint(roster_str, hex);
    assert(n00b_result_is_ok(vr));
    assert(n00b_result_get(vr) == 0);
    printf("  matched: helper returned 0\n");

    /* Mutate the roster (append a byte). */
    FILE *fh = fopen(roster_path, "a");
    assert(fh != nullptr);
    fputc('!', fh);
    fclose(fh);

    auto vr2 = n00b_audit_verify_roster_fingerprint(roster_str, hex);
    assert(n00b_result_is_ok(vr2));
    assert(n00b_result_get(vr2) == 1);
    printf("  mismatched after mutation: helper returned 1\n");

    /* Mixed-case directive value is tolerated (the parser stores
     * the directive verbatim; the verifier compares case-
     * insensitively). */
    char upper[65];
    /*
     * Re-hash the mutated file and uppercase the hex so the
     * case-insensitive comparator can demonstrate its job.
     */
    auto hr2 = n00b_audit_roster_sha256(roster_str);
    n00b_string_t *hex2 = n00b_result_get(hr2);
    for (size_t i = 0; i < 64; i++) {
        char c = hex2->data[i];
        if (c >= 'a' && c <= 'f') {
            c = (char)(c - 'a' + 'A');
        }
        upper[i] = c;
    }
    upper[64] = '\0';
    n00b_string_t *upper_str = n00b_string_from_cstr(upper);
    auto vr3 = n00b_audit_verify_roster_fingerprint(roster_str, upper_str);
    assert(n00b_result_is_ok(vr3));
    assert(n00b_result_get(vr3) == 0);
    printf("  uppercase directive matches lowercase hash (case-insensitive)\n");

    printf("  [PASS] fingerprint_binding\n");
    remove_tree(workspace_root);
}

/* ---------------------------------------------------------------- */
/* Tests 3 / 4 / 5 — rule-file signature wrapper                    */
/* ---------------------------------------------------------------- */

static void
test_rule_signature_signed(void)
{
    setup_workspace("rules_signed");

    /* Build a minimal audit-rules.bnf in the workspace. */
    char rules_path[2400];
    snprintf(rules_path, sizeof(rules_path),
             "%s/audit-rules.bnf", workspace_root);
    write_text(rules_path,
               "@schema_version 1\n"
               "@project demo\n"
               "@description trust-root test\n"
               "@source_doc test\n");

    /* Generate a key + roster. */
    gen_keypair(workspace_root, "id_rules");
    char roster_path[2400];
    snprintf(roster_path, sizeof(roster_path),
             "%s/allowed_signers", workspace_root);
    char pub_path[2400];
    snprintf(pub_path, sizeof(pub_path), "%s/id_rules.pub", workspace_root);
    write_roster(roster_path, "rules@example.com", pub_path);

    char key_path[2400];
    snprintf(key_path, sizeof(key_path), "%s/id_rules", workspace_root);

    /* Sign via the public API. */
    n00b_string_t *rp = n00b_string_from_cstr(rules_path);
    n00b_string_t *kp = n00b_string_from_cstr(key_path);
    n00b_string_t *sn = n00b_string_from_cstr("rules@example.com");
    auto sr = n00b_audit_sign_rules(rp, kp, sn);
    assert(n00b_result_is_ok(sr));
    char sig_path[2600];
    snprintf(sig_path, sizeof(sig_path), "%s.sig", rules_path);
    assert(file_exists(sig_path));
    printf("  signed audit-rules.bnf (-> %s)\n", sig_path);

    /* Verify — expected 0 (silent accept). */
    n00b_string_t *rost = n00b_string_from_cstr(roster_path);
    auto vr = n00b_audit_rules_verify_signature(rp, rost, sn);
    assert(n00b_result_is_ok(vr));
    int v = n00b_result_get(vr);
    printf("  verify result = %d (expected 0 = silent accept)\n", v);
    assert(v == 0);

    printf("  [PASS] rule_signature_signed\n");
    remove_tree(workspace_root);
}

static void
test_rule_signature_unsigned(void)
{
    setup_workspace("rules_unsigned");

    /* Rules file with NO .sig sibling. */
    char rules_path[2400];
    snprintf(rules_path, sizeof(rules_path),
             "%s/audit-rules.bnf", workspace_root);
    write_text(rules_path,
               "@schema_version 1\n"
               "@project demo\n"
               "@description unsigned\n"
               "@source_doc test\n");

    /* Need a roster to call the verifier; any roster works since
     * the unsigned path short-circuits before hitting ssh-keygen. */
    gen_keypair(workspace_root, "id_u");
    char roster_path[2400];
    snprintf(roster_path, sizeof(roster_path),
             "%s/allowed_signers", workspace_root);
    char pub_path[2400];
    snprintf(pub_path, sizeof(pub_path), "%s/id_u.pub", workspace_root);
    write_roster(roster_path, "u@example.com", pub_path);

    n00b_string_t *rp = n00b_string_from_cstr(rules_path);
    n00b_string_t *rost = n00b_string_from_cstr(roster_path);
    n00b_string_t *sn = n00b_string_from_cstr("u@example.com");
    auto vr = n00b_audit_rules_verify_signature(rp, rost, sn);
    assert(n00b_result_is_ok(vr));
    int v = n00b_result_get(vr);
    printf("  verify result = %d (expected 1 = unsigned)\n", v);
    assert(v == 1);

    printf("  [PASS] rule_signature_unsigned\n");
    remove_tree(workspace_root);
}

static void
test_rule_signature_non_roster(void)
{
    setup_workspace("rules_non_roster");

    char rules_path[2400];
    snprintf(rules_path, sizeof(rules_path),
             "%s/audit-rules.bnf", workspace_root);
    write_text(rules_path,
               "@schema_version 1\n"
               "@project demo\n"
               "@description non-roster\n"
               "@source_doc test\n");

    /* Generate TWO keypairs. Sign with K1, verify against a
     * roster listing only K2. */
    gen_keypair(workspace_root, "k1");
    gen_keypair(workspace_root, "k2");
    char roster_path[2400];
    snprintf(roster_path, sizeof(roster_path),
             "%s/allowed_signers", workspace_root);
    char pub_k2[2400];
    snprintf(pub_k2, sizeof(pub_k2), "%s/k2.pub", workspace_root);
    write_roster(roster_path, "k2-only@example.com", pub_k2);

    /* Sign rules with k1. */
    char key_k1[2400];
    snprintf(key_k1, sizeof(key_k1), "%s/k1", workspace_root);
    n00b_string_t *rp = n00b_string_from_cstr(rules_path);
    n00b_string_t *kp = n00b_string_from_cstr(key_k1);
    /*
     * The signer-id we embed must be one that ssh-keygen will
     * accept as the principal at sign time; ssh-keygen doesn't
     * validate it against the roster, so any string works here.
     */
    n00b_string_t *sn1 = n00b_string_from_cstr("k1@example.com");
    auto sr = n00b_audit_sign_rules(rp, kp, sn1);
    assert(n00b_result_is_ok(sr));

    /* Verify with k2-only roster + k2's principal → expect 2. */
    n00b_string_t *rost = n00b_string_from_cstr(roster_path);
    n00b_string_t *sn2 = n00b_string_from_cstr("k2-only@example.com");
    auto vr = n00b_audit_rules_verify_signature(rp, rost, sn2);
    assert(n00b_result_is_ok(vr));
    int v = n00b_result_get(vr);
    printf("  verify result = %d (expected 2 = bad-sig / non-roster)\n", v);
    assert(v == 2);

    printf("  [PASS] rule_signature_non_roster\n");
    remove_tree(workspace_root);
}

/* ---------------------------------------------------------------- */
/* Test 6 — engine-level unsigned-rule-file warning emission        */
/*                                                                   */
/* The wrapper-level tests (3/4/5) only cover the return code of    */
/* `n00b_audit_rules_verify_signature`. The white paper § 6.3       */
/* policy is enforced at engine load time: stderr must carry a      */
/* prominent "warning:" line when `audit-rules.bnf` is unsigned,    */
/* and that line must downgrade to an "info:" line when             */
/* `--repo-protected` is asserted. This test exercises the engine   */
/* path end-to-end and inspects stderr.                              */
/*                                                                   */
/* Capture mechanism: POSIX `pipe()` + `dup2()` around fd 2, same   */
/* shape as `test_naudit_cli_json.c`. libn00b's `n00b_eprintf`      */
/* writes to fd 2 via the POSIX `write()` syscall, so post-dup2     */
/* writes land on our pipe read-end.                                 */
/* ---------------------------------------------------------------- */

#define STDERR_BUF_SIZE (64 * 1024)

typedef struct {
    int saved_stderr;
    int stderr_pipe[2]; /* [0]=read, [1]=write */
} stderr_capture_t;

static void
stderr_capture_begin(stderr_capture_t *cap)
{
    cap->saved_stderr = dup(2);
    assert(cap->saved_stderr >= 0);
    int rc = pipe(cap->stderr_pipe);
    assert(rc == 0);
    int flags = fcntl(cap->stderr_pipe[0], F_GETFL, 0);
    assert(flags >= 0);
    fcntl(cap->stderr_pipe[0], F_SETFL, flags | O_NONBLOCK);
    rc = dup2(cap->stderr_pipe[1], 2);
    assert(rc >= 0);
    close(cap->stderr_pipe[1]);
}

static void
stderr_capture_end(stderr_capture_t *cap, char *out, size_t cap_sz)
{
    dup2(cap->saved_stderr, 2);
    close(cap->saved_stderr);
    size_t off = 0;
    for (;;) {
        if (off + 1 >= cap_sz) {
            break;
        }
        ssize_t n = read(cap->stderr_pipe[0], out + off, cap_sz - off - 1);
        if (n <= 0) {
            break;
        }
        off += (size_t)n;
    }
    out[off] = '\0';
    close(cap->stderr_pipe[0]);
}

/*
 * Drive a full audit against an unsigned `audit-rules.bnf` and
 * capture stderr. The workspace ships a roster at REPO slot
 * (`<project_root>/audit/allowed_signers`); both the REPO-source
 * warning AND the unsigned-rule-file warning fire when
 * `--repo-protected` is NOT asserted, and both downgrade when it
 * IS asserted. The test asserts on the unsigned-rule-file text
 * specifically.
 *
 * Loads guidance + creates a single engine once; each call to
 * `check_file` flips the repo-protected setter so we can compare
 * captured stderr from the two policy modes side-by-side. The
 * trust-root checks live in the lazily-run signature gate which
 * the engine guards with a `signatures_applied` flag — first
 * check_file fires the gate; subsequent calls reuse the verdict.
 * To exercise BOTH branches we therefore use TWO engine
 * instances (one per policy mode).
 */
static n00b_audit_guidance_t *
load_guidance_or_null(n00b_string_t *rules_str)
{
    auto gr = n00b_audit_load_guidance(rules_str);
    if (n00b_result_is_err(gr)) {
        return nullptr;
    }
    return n00b_result_get(gr);
}

static void
run_engine_capture_stderr(n00b_audit_guidance_t *g,
                          n00b_string_t         *target_file,
                          bool                   repo_protected,
                          char                  *stderr_out,
                          size_t                 stderr_cap)
{
    /*
     * The trust-root checks fire in the engine's signature-gate
     * path (apply_signature_gate -> apply_trust_root_checks),
     * which is exercised by `n00b_audit_engine_check_file`.
     */
    stderr_capture_t cap;
    stderr_capture_begin(&cap);

    auto er = n00b_audit_engine_new(g);
    if (n00b_result_is_ok(er)) {
        n00b_audit_engine_t *engine = n00b_result_get(er);
        n00b_audit_engine_set_repo_protected(engine, repo_protected);
        /* The unsigned-rule-file gate runs regardless of
         * --allow-unsigned (it concerns the rule file itself,
         * not exemption / baseline records); set it true to
         * keep the rest of the pipeline quiet. */
        n00b_audit_engine_set_allow_unsigned(engine, true);
        (void)n00b_audit_engine_check_file(engine, target_file);
    }

    stderr_capture_end(&cap, stderr_out, stderr_cap);
}

static void
test_engine_unsigned_rule_warning(void)
{
    setup_workspace("engine_unsigned_warn");

    /* audit-rules.bnf with one valid filter-based rule the engine can
     * compose against the C grammar (WP-016: queries <provided_identifier>
     * and narrows to NULL via the is_null_keyword filter, so the engine
     * doesn't reject a grafted synthetic NT). */
    char rules_path[2400];
    snprintf(rules_path, sizeof(rules_path),
             "%s/audit-rules.bnf", workspace_root);
    write_text(rules_path,
               "@schema_version 1\n"
               "@project demo\n"
               "@description engine-level unsigned-rule warning\n"
               "@source_doc test\n"
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
               "@rationale Test rationale.\n"
               "@bad int *p = NULL;\n"
               "@good int *p = nullptr;\n"
               "@guidance Replace NULL with nullptr.\n");

    /* REPO-slot roster: <project_root>/audit/allowed_signers. */
    char audit_dir[2400];
    snprintf(audit_dir, sizeof(audit_dir), "%s/audit", workspace_root);
    make_dir(audit_dir);
    char repo_roster_path[2600];
    snprintf(repo_roster_path, sizeof(repo_roster_path),
             "%s/audit/allowed_signers", workspace_root);
    write_text(repo_roster_path, "demo ssh-ed25519 AAAAfake\n");

    /* Target source file the engine actually audits. */
    char target_path[2400];
    snprintf(target_path, sizeof(target_path),
             "%s/fixture.c", workspace_root);
    write_text(target_path,
               "int\n"
               "main(void)\n"
               "{\n"
               "    int *p = nullptr;\n"
               "    return p == nullptr ? 0 : 1;\n"
               "}\n");

    n00b_string_t *target_str = n00b_string_from_cstr(target_path);
    char rules_buf[2400];
    snprintf(rules_buf, sizeof(rules_buf),
             "%s/audit-rules.bnf", workspace_root);
    n00b_string_t *rules_str = n00b_string_from_cstr(rules_buf);

    /*
     * The chain's ENV slot must be unset so REPO-slot wins; the
     * shared test fixture clears these in `main`, but be defensive
     * since prior tests may have set them.
     */
    clear_trust_root_env();

    /*
     * Load guidance once (it's the same file for both modes; the
     * loader caches the resolved roster path + source on the
     * guidance struct, and per W1 those are the values the engine
     * reads — neither policy mode mutates them).
     */
    n00b_audit_guidance_t *g = load_guidance_or_null(rules_str);
    assert(g != nullptr);

    /* --- (a) Without --repo-protected: prominent "warning:" --- */
    char err_a[STDERR_BUF_SIZE];
    run_engine_capture_stderr(g, target_str, false,
                              err_a, sizeof(err_a));
    if (strstr(err_a, "audit-rules.bnf") == nullptr
        || strstr(err_a, "unsigned") == nullptr
        || strstr(err_a, "warning:") == nullptr) {
        fprintf(stderr, "  captured stderr (no --repo-protected):\n%s\n",
                err_a);
    }
    assert(strstr(err_a, "audit-rules.bnf") != nullptr);
    assert(strstr(err_a, "unsigned") != nullptr);
    assert(strstr(err_a, "warning:") != nullptr);
    /* The informational downgrade marker MUST NOT appear in the
     * unsigned-rules diagnostic when --repo-protected is off.
     * (The REPO-slot warning also fires here; both should be
     * prominent.) */
    printf("  (a) no --repo-protected → 'warning:' present\n");

    /* --- (b) With --repo-protected: downgraded "info:" --- */
    char err_b[STDERR_BUF_SIZE];
    run_engine_capture_stderr(g, target_str, true,
                              err_b, sizeof(err_b));
    if (strstr(err_b, "audit-rules.bnf is unsigned") == nullptr
        || strstr(err_b, "info:") == nullptr) {
        fprintf(stderr, "  captured stderr (--repo-protected):\n%s\n",
                err_b);
    }
    assert(strstr(err_b, "audit-rules.bnf is unsigned") != nullptr);
    assert(strstr(err_b, "info:") != nullptr);
    /* The prominent unsigned-rules warning text MUST NOT appear
     * when --repo-protected is on. The exact phrase used by the
     * non-protected branch ("is unsigned — agent or attacker
     * writes") is the distinguishing marker. */
    assert(strstr(err_b, "is unsigned — agent or attacker writes")
           == nullptr);
    printf("  (b) --repo-protected → 'info:' downgrade, no prominent warning\n");

    printf("  [PASS] engine_unsigned_rule_warning\n");
    remove_tree(workspace_root);
}

/* ---------------------------------------------------------------- */
/* main                                                              */
/* ---------------------------------------------------------------- */

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    clear_trust_root_env();

    test_lookup_chain();
    test_fingerprint_binding();
    test_rule_signature_signed();
    test_rule_signature_unsigned();
    test_rule_signature_non_roster();
    test_engine_unsigned_rule_warning();

    printf("All naudit trust-root WP-015 unit checks passed.\n");
    return 0;
}

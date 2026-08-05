/*
 * WP-013 Phase 1 — unit tests for the blame-lineage anchor.
 *
 * Test harness shape:
 *   - Each test creates a fresh tmp directory.
 *   - libgit2 initializes a repository there
 *     (`git_repository_init`), drops fixture files, builds the
 *     index, and commits via libgit2 native primitives (no shell
 *     subprocess).
 *   - The tests then exercise `n00b_audit_blame_signing_commit`
 *     and `n00b_audit_blame_traces_to` against the constructed
 *     history.
 *
 * Per preflight item 6, six sub-tests:
 *   1. line-anchored exemption matches.
 *   2. line shift (insert blank lines above) still matches.
 *   3. copy-paste does NOT propagate.
 *   4. substantive edit breaks the chain.
 *   5. rename file (via libgit2 index-move) still anchors.
 *   6. pre-commit fingerprint fallback.
 *
 * Bootstrap shape mirrors `test_naudit_exemption.c` per the relaxed
 * test-file convention: libc `<assert.h>` + `<stdio.h>` are allowed
 * for harness scaffolding (NCC.md "NO LIBC ALLOWED" exemption for
 * test files), as is direct libgit2 use for the in-test git
 * primitives.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "test_portability.h"

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "util/path.h"

#include "naudit/naudit.h"
#include "naudit/blame.h"
#include "naudit/exemption.h"

#include <git2.h>

/* ---------------------------------------------------------------- */
/* Test harness helpers                                             */
/* ---------------------------------------------------------------- */

/*
 * Create a fresh empty directory under `<TMPDIR>/naudit-blame-XXXX/`
 * for a single test. The string is fed to libgit2 + naudit; we keep
 * the result around for diagnostics (no cleanup — tests run in
 * disposable containers / dev tmp dir, and cleanup-on-failure can
 * mask real bugs).
 */
static n00b_string_t *
mkrepo_dir(const char *test_name)
{
    char tmpl[1024];
    const char *base = getenv("TMPDIR");
    if (!base || !*base) {
        base = "/tmp";
    }
    /*
     * Trim trailing slash from base if present — mkdtemp expects an
     * exact template ending in XXXXXX.
     */
    size_t bl = strlen(base);
    if (bl > 0 && base[bl - 1] == '/') {
        bl--;
    }
    int n = snprintf(tmpl, sizeof(tmpl),
                     "%.*s/naudit-blame-%s-XXXXXX",
                     (int)bl, base, test_name);
    assert(n > 0 && (size_t)n < sizeof(tmpl));
    char *got = mkdtemp(tmpl);
    assert(got != nullptr);
    return n00b_string_from_cstr(got);
}

/*
 * Write `content` to `<dir>/<rel_path>` using a plain POSIX
 * open/write. Tests run inside the test-file-relaxed convention; we
 * don't go through libn00b's n00b_file_open here because the engine
 * + libgit2 are the things under test and we want zero behavioral
 * coupling between the harness and the libraries it exercises.
 */
static void
write_file(n00b_string_t *dir, const char *rel_path, const char *content)
{
    char full[2048];
    int n = snprintf(full, sizeof(full), "%s/%s", dir->data, rel_path);
    assert(n > 0 && (size_t)n < sizeof(full));
    /*
     * Create parent directory if rel_path contains a slash.
     */
    char *slash = strrchr(full, '/');
    if (slash) {
        size_t parent_len = (size_t)(slash - full);
        char parent[2048];
        memcpy(parent, full, parent_len);
        parent[parent_len] = '\0';
        /* mkdir -p one level (good enough for our fixtures). */
        struct stat st;
        if (stat(parent, &st) != 0) {
            mkdir(parent, 0700);
        }
    }
    int fd = open(full, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0);
    size_t len = strlen(content);
    ssize_t w = write(fd, content, len);
    assert((size_t)w == len);
    close(fd);
}

/*
 * Commit every tracked file (the index after this index's bypath
 * adds) as a fresh commit. Returns the new commit OID.
 *
 * If `parent_oid_hex` is non-null, the new commit has that as its
 * parent; otherwise it's a root commit.
 */
static void
commit_all(git_repository *repo,
           const char *const *paths, size_t npaths,
           const char *message,
           const char *parent_oid_hex,
           git_time_t when,
           git_oid *out_oid)
{
    git_index *idx = nullptr;
    int rc = git_repository_index(&idx, repo);
    assert(rc == 0 && idx != nullptr);

    for (size_t i = 0; i < npaths; i++) {
        rc = git_index_add_bypath(idx, paths[i]);
        assert(rc == 0);
    }
    rc = git_index_write(idx);
    assert(rc == 0);

    git_oid tree_oid;
    rc = git_index_write_tree(&tree_oid, idx);
    assert(rc == 0);
    git_index_free(idx);

    git_tree *tree = nullptr;
    rc = git_tree_lookup(&tree, repo, &tree_oid);
    assert(rc == 0 && tree != nullptr);

    git_signature *sig = nullptr;
    rc = git_signature_new(&sig, "naudit-test", "naudit@test", when, 0);
    assert(rc == 0);

    git_commit *parent = nullptr;
    if (parent_oid_hex) {
        git_oid parent_oid;
        rc = git_oid_fromstr(&parent_oid, parent_oid_hex);
        assert(rc == 0);
        rc = git_commit_lookup(&parent, repo, &parent_oid);
        assert(rc == 0);
    }
    const git_commit *parents[1];
    parents[0] = parent;

    rc = git_commit_create(out_oid, repo, "HEAD", sig, sig, "UTF-8",
                           message, tree, parent ? 1 : 0,
                           parent ? parents : nullptr);
    assert(rc == 0);

    if (parent) {
        git_commit_free(parent);
    }
    git_signature_free(sig);
    git_tree_free(tree);
}

/*
 * Initialize a fresh repository at `dir` (non-bare). Returns an
 * owned `git_repository *` the caller must `git_repository_free`.
 */
static git_repository *
init_repo(n00b_string_t *dir)
{
    git_repository *repo = nullptr;
    int rc = git_repository_init(&repo, dir->data, /*is_bare=*/0);
    assert(rc == 0 && repo != nullptr);
    return repo;
}

/*
 * Common fixture: a small C source file with NULL on a specific
 * line. Mirrors `fixture_null.c` shape. The exemption record's
 * `locator_line` will point at the NULL line; tests vary how the
 * surrounding text moves between the signing commit and the
 * audit-time working tree.
 */
static const char *FIXTURE_NULL_V1 =
    "int main(void) {\n"
    "    int *p = NULL;\n"
    "    return 0;\n"
    "}\n";

/*
 * Build an exemption record by hand for the test. We fill the
 * fields the matcher consults: rule_id (some plausible content
 * hash), region_fingerprint (matching the NULL line's
 * canonicalized form), locator_line, locator_end_line,
 * source_file. version, rationale, signer_id, etc. are
 * informational for these tests.
 */
static n00b_audit_exemption_t *
build_exemption(n00b_string_t *source_file,
                int64_t        locator_line,
                int64_t        locator_end_line,
                n00b_string_t *rule_id,
                n00b_string_t *fingerprint)
{
    n00b_audit_exemption_t *ex = n00b_alloc(n00b_audit_exemption_t);
    ex->version            = 1;
    ex->rule_id            = rule_id;
    ex->rule_name          = n00b_string_from_cstr("n00b.s2_1.null");
    ex->file_path          = n00b_string_from_cstr("fixture.c");
    ex->locator_line       = locator_line;
    ex->locator_col        = 1;
    ex->locator_end_line   = locator_end_line;
    ex->locator_end_col    = 999;
    ex->region_fingerprint = fingerprint;
    ex->rationale          = n00b_string_from_cstr("test");
    ex->signer_id          = n00b_string_from_cstr("naudit-test");
    ex->approved_at        = n00b_string_from_cstr("2026-05-28");
    ex->expires_at         = n00b_string_empty();
    ex->source_file        = source_file;
    return ex;
}

/*
 * Build a fake violation for the matcher. We carry rule->content_hash
 * so the matcher's first gate passes; `line` and `end_line` drive
 * the blame trace.
 */
static n00b_audit_violation_t *
build_violation(n00b_string_t *file,
                int64_t        line,
                int64_t        end_line,
                n00b_string_t *rule_id,
                n00b_string_t *fingerprint)
{
    n00b_audit_rule_t *rule = n00b_alloc(n00b_audit_rule_t);
    rule->id            = n00b_string_from_cstr("n00b.s2_1.null");
    rule->content_hash  = rule_id;
    rule->guidance      = n00b_string_empty();
    n00b_audit_violation_t *v = n00b_alloc(n00b_audit_violation_t);
    v->file               = file;
    v->line               = line;
    v->column             = 1;
    v->end_line           = end_line;
    v->end_column         = 999;
    v->rule               = rule;
    v->rewrite            = nullptr;
    v->region_fingerprint = fingerprint;
    return v;
}

/* Build joined path string `<dir>/<rel>`. */
static n00b_string_t *
joinp(n00b_string_t *dir, const char *rel)
{
    char buf[2048];
    int n = snprintf(buf, sizeof(buf), "%s/%s", dir->data, rel);
    assert(n > 0 && (size_t)n < sizeof(buf));
    return n00b_string_from_cstr(buf);
}

/* ---------------------------------------------------------------- */
/* Test 1: line-anchored exemption matches                          */
/* ---------------------------------------------------------------- */

/*
 * Commit fixture.c (with NULL on line 2). Commit an exemption file.
 * Verify that:
 *   - signing_commit lookup on the exemption file returns the
 *     commit OID we used.
 *   - traces_to from the audit-time NULL line back to line 2 of
 *     the signing commit succeeds.
 *
 * This is the trivial "same file unchanged after the signing
 * commit" case.
 */
static void
test_line_anchored(void)
{
    n00b_string_t  *dir  = mkrepo_dir("01-line");
    git_repository *repo = init_repo(dir);

    write_file(dir, "fixture.c", FIXTURE_NULL_V1);
    write_file(dir, "exemption.bnf", "@exemption test\n  rule_id: x\n");

    git_oid commit1;
    const char *files1[] = {"fixture.c"};
    commit_all(repo, files1, 1, "add fixture", nullptr, 1000, &commit1);

    git_oid commit2;
    char commit1_hex[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(commit1_hex, sizeof(commit1_hex), &commit1);
    const char *files2[] = {"exemption.bnf"};
    commit_all(repo, files2, 1, "add exemption", commit1_hex, 2000, &commit2);

    git_repository_free(repo);

    /* Signing commit on the exemption file == commit2. */
    n00b_string_t *exemption_path = joinp(dir, "exemption.bnf");
    n00b_option_t(n00b_string_t *) signing_opt =
        n00b_audit_blame_signing_commit(dir, exemption_path);
    assert(n00b_option_is_set(signing_opt));
    n00b_string_t *signing = n00b_option_get(signing_opt);
    char commit2_hex[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(commit2_hex, sizeof(commit2_hex), &commit2);
    assert(strcmp(signing->data, commit2_hex) == 0);

    /* Traces_to: finding on line 2 of fixture.c → exempted 2..2 at
     * commit1 (the introducing commit of fixture.c). */
    n00b_string_t *audited = joinp(dir, "fixture.c");
    char commit1_hex2[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(commit1_hex2, sizeof(commit1_hex2), &commit1);
    n00b_string_t *commit1_hex_s = n00b_string_from_cstr(commit1_hex2);
    bool ok = n00b_audit_blame_traces_to(dir, audited, 2, 2,
                                          commit1_hex_s, 2, 2, 0);
    assert(ok);
    printf("  [PASS] test_line_anchored\n");
}

/* ---------------------------------------------------------------- */
/* Test 2: line shift still matches                                 */
/* ---------------------------------------------------------------- */

/*
 * Commit fixture.c then add two blank lines above the NULL line in
 * a fresh commit. The NULL has shifted from line 2 to line 4 in
 * the working tree, but blame still attributes line 4 to commit1's
 * line 2. `traces_to` from line 4 against the introducing commit's
 * range 2..2 should still succeed.
 */
static void
test_line_shift(void)
{
    n00b_string_t  *dir  = mkrepo_dir("02-shift");
    git_repository *repo = init_repo(dir);

    write_file(dir, "fixture.c", FIXTURE_NULL_V1);

    git_oid commit1;
    const char *files1[] = {"fixture.c"};
    commit_all(repo, files1, 1, "add fixture", nullptr, 1000, &commit1);

    /*
     * Add 2 blank lines above the NULL. Now NULL is on line 4.
     */
    const char *shifted =
        "\n"
        "\n"
        "int main(void) {\n"
        "    int *p = NULL;\n"
        "    return 0;\n"
        "}\n";
    write_file(dir, "fixture.c", shifted);

    git_oid commit2;
    char commit1_hex[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(commit1_hex, sizeof(commit1_hex), &commit1);
    commit_all(repo, files1, 1, "shift lines", commit1_hex, 2000, &commit2);

    git_repository_free(repo);

    n00b_string_t *audited = joinp(dir, "fixture.c");
    char commit1_hex2[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(commit1_hex2, sizeof(commit1_hex2), &commit1);
    n00b_string_t *commit1_hex_s = n00b_string_from_cstr(commit1_hex2);
    /* Finding now at line 4; exempted range was 2..2 at commit1. */
    bool ok = n00b_audit_blame_traces_to(dir, audited, 4, 4,
                                          commit1_hex_s, 2, 2, 0);
    assert(ok);
    printf("  [PASS] test_line_shift\n");
}

/* ---------------------------------------------------------------- */
/* Test 3: copy-paste does NOT propagate                            */
/* ---------------------------------------------------------------- */

/*
 * Commit fixture.c. Then add a second file `copy.c` containing the
 * exact same NULL line (textual paste) and commit it. blame on
 * copy.c attributes the NULL line to the SECOND commit (the
 * paste), not commit1's NULL line.
 *
 * `traces_to` from copy.c's NULL line, against commit1 + exempted
 * range 2..2, MUST return false.
 */
static void
test_copy_paste(void)
{
    n00b_string_t  *dir  = mkrepo_dir("03-copy");
    git_repository *repo = init_repo(dir);

    write_file(dir, "fixture.c", FIXTURE_NULL_V1);

    git_oid commit1;
    const char *files1[] = {"fixture.c"};
    commit_all(repo, files1, 1, "add fixture", nullptr, 1000, &commit1);

    /* Paste fixture into copy.c (verbatim copy, not a git mv). */
    write_file(dir, "copy.c", FIXTURE_NULL_V1);

    git_oid commit2;
    char commit1_hex[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(commit1_hex, sizeof(commit1_hex), &commit1);
    const char *files2[] = {"copy.c"};
    commit_all(repo, files2, 1, "paste copy", commit1_hex, 2000, &commit2);

    git_repository_free(repo);

    n00b_string_t *copy = joinp(dir, "copy.c");
    char commit1_hex2[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(commit1_hex2, sizeof(commit1_hex2), &commit1);
    n00b_string_t *commit1_hex_s = n00b_string_from_cstr(commit1_hex2);
    bool ok = n00b_audit_blame_traces_to(dir, copy, 2, 2,
                                          commit1_hex_s, 2, 2, 0);
    /* Should NOT match — blame attributes copy.c's lines to
     * commit2 (the paste), not commit1. */
    assert(!ok);
    printf("  [PASS] test_copy_paste\n");
}

/* ---------------------------------------------------------------- */
/* Test 4: substantive edit breaks the chain                        */
/* ---------------------------------------------------------------- */

/*
 * Commit fixture.c. Then rewrite the function body around the
 * exempted region so the NULL line itself changes. Blame on the
 * new line attributes it to the second commit, not commit1.
 *
 * `traces_to` against commit1 must return false.
 */
static void
test_substantive_edit(void)
{
    n00b_string_t  *dir  = mkrepo_dir("04-edit");
    git_repository *repo = init_repo(dir);

    write_file(dir, "fixture.c", FIXTURE_NULL_V1);

    git_oid commit1;
    const char *files1[] = {"fixture.c"};
    commit_all(repo, files1, 1, "add fixture", nullptr, 1000, &commit1);

    /*
     * Rewrite the NULL line itself (change variable name) so blame
     * attributes the new line to commit2.
     */
    const char *edited =
        "int main(void) {\n"
        "    int *qq_renamed = NULL;\n"
        "    return 0;\n"
        "}\n";
    write_file(dir, "fixture.c", edited);

    git_oid commit2;
    char commit1_hex[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(commit1_hex, sizeof(commit1_hex), &commit1);
    commit_all(repo, files1, 1, "rewrite", commit1_hex, 2000, &commit2);

    git_repository_free(repo);

    n00b_string_t *audited = joinp(dir, "fixture.c");
    char commit1_hex2[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(commit1_hex2, sizeof(commit1_hex2), &commit1);
    n00b_string_t *commit1_hex_s = n00b_string_from_cstr(commit1_hex2);
    bool ok = n00b_audit_blame_traces_to(dir, audited, 2, 2,
                                          commit1_hex_s, 2, 2, 0);
    /* Line was rewritten — chain broken. */
    assert(!ok);
    printf("  [PASS] test_substantive_edit\n");
}

/* ---------------------------------------------------------------- */
/* Test 5: rename file still anchors                                */
/* ---------------------------------------------------------------- */

/*
 * Commit fixture.c with NULL on line 2. Then `git mv fixture.c
 * renamed.c` (we do this via libgit2 index ops: remove fixture.c,
 * add renamed.c with the same bytes). Blame on renamed.c should
 * still trace back through libgit2's rename detection to commit1's
 * fixture.c.
 *
 * `traces_to` against commit1's range 2..2 should succeed.
 *
 * NOTE: libgit2's blame rename detection is driven by
 * index/diff similarity heuristics, not the `TRACK_COPIES` flags
 * (which are documented as reserved-for-future-use in 1.9.3).
 * Renames work in 1.9.3 today.
 */
static void
test_rename(void)
{
    n00b_string_t  *dir  = mkrepo_dir("05-rename");
    git_repository *repo = init_repo(dir);

    write_file(dir, "fixture.c", FIXTURE_NULL_V1);

    git_oid commit1;
    const char *files1[] = {"fixture.c"};
    commit_all(repo, files1, 1, "add fixture", nullptr, 1000, &commit1);

    /*
     * "Rename" via the filesystem + index. We remove fixture.c,
     * write renamed.c with the same bytes, and commit. libgit2's
     * blame rename heuristic should follow.
     */
    {
        char full[2048];
        snprintf(full, sizeof(full), "%s/fixture.c", dir->data);
        unlink(full);
    }
    write_file(dir, "renamed.c", FIXTURE_NULL_V1);

    /* Update the index: remove fixture.c, add renamed.c. */
    git_index *idx = nullptr;
    int rc = git_repository_index(&idx, repo);
    assert(rc == 0);
    rc = git_index_remove_bypath(idx, "fixture.c");
    assert(rc == 0);
    rc = git_index_add_bypath(idx, "renamed.c");
    assert(rc == 0);
    rc = git_index_write(idx);
    assert(rc == 0);
    git_index_free(idx);

    git_oid commit2;
    char commit1_hex[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(commit1_hex, sizeof(commit1_hex), &commit1);
    /* Commit_all rewrites the index; instead build a commit
     * referencing the index we just wrote. Use the same pattern. */
    {
        git_index *idx2 = nullptr;
        rc = git_repository_index(&idx2, repo);
        assert(rc == 0);
        git_oid tree_oid;
        rc = git_index_write_tree(&tree_oid, idx2);
        assert(rc == 0);
        git_index_free(idx2);
        git_tree *tree = nullptr;
        rc = git_tree_lookup(&tree, repo, &tree_oid);
        assert(rc == 0);
        git_signature *sig = nullptr;
        rc = git_signature_new(&sig, "naudit-test", "naudit@test",
                               2000, 0);
        assert(rc == 0);
        git_commit *parent = nullptr;
        rc = git_commit_lookup(&parent, repo, &commit1);
        assert(rc == 0);
        const git_commit *parents[1] = {parent};
        rc = git_commit_create(&commit2, repo, "HEAD", sig, sig,
                               "UTF-8", "rename", tree, 1, parents);
        assert(rc == 0);
        git_commit_free(parent);
        git_signature_free(sig);
        git_tree_free(tree);
    }

    git_repository_free(repo);

    n00b_string_t *audited = joinp(dir, "renamed.c");
    char commit1_hex2[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(commit1_hex2, sizeof(commit1_hex2), &commit1);
    n00b_string_t *commit1_hex_s = n00b_string_from_cstr(commit1_hex2);
    bool ok = n00b_audit_blame_traces_to(dir, audited, 2, 2,
                                          commit1_hex_s, 2, 2, 0);
    /*
     * libgit2 1.9.3's blame DOES follow file renames at this
     * granularity (a fresh file with identical bytes in the
     * working tree, after an `index_remove_bypath` + new
     * `index_add_bypath`, gets attributed back to the original
     * file's introducing commit). This is the rename-tracking
     * property the white paper § 4.5 documents — and it works
     * today in 1.9.3 via the index-similarity heuristic that
     * underlies the blame algorithm, even though the explicit
     * `TRACK_COPIES_*` flags are documented as reserved-for-
     * future-use.
     */
    assert(ok);
    printf("  [PASS] test_rename (libgit2 1.9.3 follows the "
           "rename via index-similarity blame)\n");
}

/* ---------------------------------------------------------------- */
/* Test 6: pre-commit fingerprint fallback                          */
/* ---------------------------------------------------------------- */

/*
 * Init a repo. Commit fixture.c. Create exemption.bnf in the
 * working tree but do NOT commit it. `signing_commit` lookup must
 * return a "none" option (no commit introduced exemption.bnf yet).
 *
 * Then run the higher-level `n00b_audit_exemption_match` and
 * verify it falls back to fingerprint-only matching (succeeds
 * when fingerprints match; fails when they don't). This exercises
 * the documented degradation path.
 */
static void
test_precommit_fallback(void)
{
    n00b_string_t  *dir  = mkrepo_dir("06-precommit");
    git_repository *repo = init_repo(dir);

    write_file(dir, "fixture.c", FIXTURE_NULL_V1);

    git_oid commit1;
    const char *files1[] = {"fixture.c"};
    commit_all(repo, files1, 1, "add fixture", nullptr, 1000, &commit1);
    git_repository_free(repo);

    /* Drop exemption.bnf but do NOT commit. */
    write_file(dir, "exemption.bnf", "@exemption draft\n  rule_id: x\n");

    /* Signing commit lookup should return a "none" option. */
    n00b_string_t *exemption_path = joinp(dir, "exemption.bnf");
    n00b_option_t(n00b_string_t *) signing_opt =
        n00b_audit_blame_signing_commit(dir, exemption_path);
    assert(!n00b_option_is_set(signing_opt));

    /*
     * Now exercise the higher-level matcher. We build an exemption
     * with a known rule_id + fingerprint, and a violation whose
     * fingerprint MATCHES it. The matcher should take the
     * fingerprint-only fallback (since signing_commit is unset) and
     * return true.
     */
    n00b_string_t *rule_id = n00b_string_from_cstr(
        "cafef00dcafef00dcafef00dcafef00d");
    n00b_string_t *fp = n00b_string_from_cstr(
        "deadbeefdeadbeefdeadbeefdeadbeef");
    n00b_audit_exemption_t *ex = build_exemption(
        exemption_path, 2, 2, rule_id, fp);
    n00b_audit_violation_t *v = build_violation(
        joinp(dir, "fixture.c"), 2, 2, rule_id, fp);
    bool ok = n00b_audit_exemption_match(ex, v, dir, 0);
    assert(ok);

    /* Mismatched fingerprint: matcher returns false even in the
     * fallback path. */
    v->region_fingerprint = n00b_string_from_cstr(
        "0000000000000000000000000000abcd");
    ok = n00b_audit_exemption_match(ex, v, dir, 0);
    assert(!ok);

    printf("  [PASS] test_precommit_fallback\n");
}

/* ---------------------------------------------------------------- */
/* Entry                                                            */
/* ---------------------------------------------------------------- */

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    /*
     * The test harness drives libgit2 directly (repo_init, index,
     * commit) BEFORE any naudit blame entry point runs, so the
     * auto-init inside the naudit module isn't reached on the
     * fixture-building path. Initialize libgit2 explicitly here.
     * The blame module's auto-init is idempotent — it tracks
     * status via its own per-process flag and won't double-init.
     */
    bool inited = n00b_audit_blame_init();
    assert(inited);

    test_line_anchored();
    test_line_shift();
    test_copy_paste();
    test_substantive_edit();
    test_rename();
    test_precommit_fallback();

    printf("All naudit blame WP-013 unit checks passed.\n");
    return 0;
}

/*
 * WP-001 Phase 5 regression test — CLI driver (JSON output).
 *
 * Exercises the library-shaped entry `n00b_audit_run_cli(argc, argv)`
 * with `--format=json` against the two production fixtures:
 *
 *   1. fixture_null.c + guidance_phase4.bnf → ok-int 1, captured
 *      stdout parses as a JSON object whose `violations` array is
 *      non-empty, whose first entry's `rule_id` equals
 *      `n00b.s2_1.null`, and whose `summary.error_count` equals the
 *      `violations` length. No `severity` key anywhere.
 *   2. fixture_nullptr.c + guidance_phase4.bnf → ok-int 0, captured
 *      stdout parses as a JSON object whose `violations` array is
 *      empty and whose `summary.error_count` equals 0. No `severity`
 *      key anywhere.
 *
 * Capture mechanism: POSIX `pipe()` + `dup2()` around fd 1 (stdout)
 * and fd 2 (stderr) — same shape as Phase 4's `test_audit_cli.c`.
 * libn00b's fd_writer holds the integer fd number and writes via the
 * POSIX `write()` syscall, so post-dup2 writes land on our pipe
 * read-end. The relaxed test-file convention (NCC.md "NO LIBC
 * ALLOWED" exemption for test sources) makes libc `<unistd.h>` /
 * `<assert.h>` / `<stdio.h>` / `<string.h>` fair game for harness
 * scaffolding.
 *
 * Bootstrap shape mirrors test/unit/test_audit_cli.c: `n00b_init_simple`
 * first thing, fixture-path discovery via the
 * `N00B_AUDIT_TEST_FIXTURE_DIR` macro (no hardcoded paths — set by
 * test/meson.build).
 *
 * Per project DECISIONS.md D-005, there is no `severity` field
 * anywhere in this test — the assertions explicitly verify D-005's
 * "no severity key anywhere" carveout against the parsed JSON tree.
 *
 * The fixture .c files contain `NULL` and `nullptr` as PARSE-TARGET
 * input; the n00b-api-guidelines § 2.1 NULL→nullptr rule does NOT
 * apply to them.
 */

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "test_portability.h"

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "adt/list.h"
#include "parsers/json.h"

#include "naudit/naudit.h"
#include "naudit/errors.h"

#ifndef N00B_AUDIT_TEST_FIXTURE_DIR
#error "N00B_AUDIT_TEST_FIXTURE_DIR must be set by the build (see test/meson.build)"
#endif

#define CAPTURE_BUF_SIZE (64 * 1024)

/* ------------------------------------------------------------ */
/* Fixture-path + argv builders.                                */
/* ------------------------------------------------------------ */

static n00b_string_t *
fixture_path(const char *fname)
{
    char buf[1024];
    int  n = snprintf(buf, sizeof(buf), "%s/%s",
                      N00B_AUDIT_TEST_FIXTURE_DIR, fname);
    assert(n > 0 && (size_t)n < sizeof(buf));
    return n00b_string_from_cstr(buf);
}

/* ------------------------------------------------------------ */
/* Stdout/stderr capture via POSIX pipe + dup2 — same shape as  */
/* test_audit_cli.c.                                            */
/* ------------------------------------------------------------ */

typedef struct {
    int  saved_stdout;
    int  saved_stderr;
    int  stdout_pipe[2]; /* [0]=read, [1]=write */
    int  stderr_pipe[2];
} capture_t;

static void
capture_begin(capture_t *cap)
{
    cap->saved_stdout = dup(1);
    cap->saved_stderr = dup(2);
    assert(cap->saved_stdout >= 0);
    assert(cap->saved_stderr >= 0);

    int rc = pipe(cap->stdout_pipe);
    assert(rc == 0);
    rc = pipe(cap->stderr_pipe);
    assert(rc == 0);

    int flags = fcntl(cap->stdout_pipe[0], F_GETFL, 0);
    assert(flags >= 0);
    fcntl(cap->stdout_pipe[0], F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(cap->stderr_pipe[0], F_GETFL, 0);
    assert(flags >= 0);
    fcntl(cap->stderr_pipe[0], F_SETFL, flags | O_NONBLOCK);

    rc = dup2(cap->stdout_pipe[1], 1);
    assert(rc >= 0);
    rc = dup2(cap->stderr_pipe[1], 2);
    assert(rc >= 0);

    close(cap->stdout_pipe[1]);
    close(cap->stderr_pipe[1]);
}

static void
capture_end(capture_t *cap, char *stdout_out, size_t stdout_cap,
            char *stderr_out, size_t stderr_cap)
{
    dup2(cap->saved_stdout, 1);
    dup2(cap->saved_stderr, 2);
    close(cap->saved_stdout);
    close(cap->saved_stderr);

    size_t off = 0;
    for (;;) {
        if (off + 1 >= stdout_cap) break;
        ssize_t n = read(cap->stdout_pipe[0], stdout_out + off,
                          stdout_cap - off - 1);
        if (n <= 0) break;
        off += (size_t)n;
    }
    stdout_out[off] = '\0';

    off = 0;
    for (;;) {
        if (off + 1 >= stderr_cap) break;
        ssize_t n = read(cap->stderr_pipe[0], stderr_out + off,
                          stderr_cap - off - 1);
        if (n <= 0) break;
        off += (size_t)n;
    }
    stderr_out[off] = '\0';

    close(cap->stdout_pipe[0]);
    close(cap->stderr_pipe[0]);
}

/* ------------------------------------------------------------ */
/* JSON helpers — walk the parsed tree through the public JSON accessors. */
/* ------------------------------------------------------------ */

/*
 * Returns true iff the JSON object node carries a key with the supplied
 * C-string name.
 */
static bool
json_object_has_key(n00b_json_node_t *obj, const char *key)
{
    if (!obj || !n00b_json_is_object(obj)) {
        return false;
    }
    return n00b_json_object_get_cstr(obj, key) != nullptr;
}

/*
 * Look up a JSON object's child node by C-string key. Returns
 * nullptr if missing or if the parent isn't an object. Mirrors the
 * Phase 2 loader's `json_obj_get_or_null`.
 */
static n00b_json_node_t *
json_object_get(n00b_json_node_t *obj, const char *key)
{
    if (!obj || !n00b_json_is_object(obj)) {
        return nullptr;
    }
    return n00b_json_object_get_cstr(obj, key);
}

/* ------------------------------------------------------------ */
/* Test cases.                                                  */
/* ------------------------------------------------------------ */

static n00b_string_t **
build_argv6(n00b_string_t *prog, n00b_string_t *guidance_flag,
            n00b_string_t *guidance_val, n00b_string_t *format_flag,
            n00b_string_t *format_val, n00b_string_t *positional,
            int *argc_out)
{
    n00b_string_t **argv = (n00b_string_t **)n00b_alloc_array(
        n00b_string_t *, 7);
    argv[0] = prog;
    argv[1] = guidance_flag;
    argv[2] = guidance_val;
    argv[3] = format_flag;
    argv[4] = format_val;
    argv[5] = positional;
    argv[6] = nullptr;
    *argc_out = 6;
    return argv;
}

static void
test_fixture_null_json(void)
{
    int argc = 0;
    n00b_string_t **argv = build_argv6(
        n00b_string_from_cstr("n00b-audit"),
        n00b_string_from_cstr("--guidance"),
        fixture_path("guidance_phase4.bnf"),
        n00b_string_from_cstr("--format"),
        n00b_string_from_cstr("json"),
        fixture_path("fixture_null.c"),
        &argc);

    capture_t cap;
    capture_begin(&cap);
    n00b_result_t(int) r = n00b_audit_run_cli(argc, argv);
    static char out[CAPTURE_BUF_SIZE];
    static char err[CAPTURE_BUF_SIZE];
    capture_end(&cap, out, sizeof(out), err, sizeof(err));

    if (n00b_result_is_err(r)) {
        fprintf(stderr,
                "  fixture_null run_cli returned err code=%d\n",
                n00b_result_get_err(r));
        fprintf(stderr, "  captured stderr: %s\n", err);
    }
    assert(n00b_result_is_ok(r));
    int code = n00b_result_get(r);
    if (code != 1) {
        fprintf(stderr, "  expected exit-int 1 (violations), got %d\n", code);
        fprintf(stderr, "  captured stdout: %s\n", out);
        fprintf(stderr, "  captured stderr: %s\n", err);
    }
    assert(code == 1);
    assert(strlen(out) > 0);

    /* Round-trip parse the captured JSON. */
    const char *jerr = nullptr;
    n00b_json_node_t *root = n00b_json_parse(out, strlen(out), &jerr);
    if (!root) {
        fprintf(stderr, "  JSON parse failed: %s\n",
                jerr ? jerr : "(no message)");
        fprintf(stderr, "  captured stdout: %s\n", out);
    }
    assert(root != nullptr);
    assert(n00b_json_is_object(root));

    /* `violations` is an array, non-empty. */
    n00b_json_node_t *viol = json_object_get(root, "violations");
    assert(viol != nullptr);
    assert(n00b_json_is_array(viol));
    size_t viol_len = n00b_json_array_len(viol);
    assert(viol_len >= 1);

    /* First violation carries the expected keys + rule_id. */
    n00b_json_node_t *v0 = n00b_json_array_get(viol, 0);
    assert(v0 != nullptr);
    assert(n00b_json_is_object(v0));
    assert(json_object_has_key(v0, "file"));
    assert(json_object_has_key(v0, "line"));
    assert(json_object_has_key(v0, "column"));
    assert(json_object_has_key(v0, "rule_id"));
    assert(json_object_has_key(v0, "message"));
    assert(json_object_has_key(v0, "doc_section"));
    assert(json_object_has_key(v0, "good_example"));

    n00b_json_node_t *rid = json_object_get(v0, "rule_id");
    assert(rid != nullptr);
    assert(n00b_json_is_string(rid));
    assert(n00b_json_as_cstr(rid) != nullptr);
    assert(strcmp(n00b_json_as_cstr(rid), "n00b.s2_1.null") == 0);

    /* WP-007 Phase 2: the violation must carry a "rewrite" key whose
     * value is the rewrite template ("nullptr"). The guidance_phase4
     * fixture's rule 1 has a rewrite block in this WP. */
    assert(json_object_has_key(v0, "rewrite"));
    n00b_json_node_t *rwn = json_object_get(v0, "rewrite");
    assert(rwn != nullptr);
    assert(n00b_json_is_string(rwn));
    const char *rewrite = n00b_json_as_cstr(rwn);
    assert(rewrite != nullptr);
    if (strcmp(rewrite, "nullptr") != 0) {
        fprintf(stderr,
                "  expected rewrite=\"nullptr\"; got \"%s\"\n", rewrite);
    }
    assert(strcmp(rewrite, "nullptr") == 0);

    /* `summary.error_count` equals the violations-array length. */
    n00b_json_node_t *summary = json_object_get(root, "summary");
    assert(summary != nullptr);
    assert(n00b_json_is_object(summary));
    n00b_json_node_t *ec = json_object_get(summary, "error_count");
    assert(ec != nullptr);
    assert(n00b_json_is_int(ec));
    assert((size_t)n00b_json_as_i64(ec) == viol_len);

    /* D-005 carveout: no `severity` key anywhere. Walk the known
     * objects (root, summary, every violation) and assert. Also
     * substring-check the raw bytes as a belt-and-braces guard
     * against an unforeseen path emitting the field literally. */
    assert(!json_object_has_key(root, "severity"));
    assert(!json_object_has_key(summary, "severity"));
    for (size_t i = 0; i < viol_len; i++) {
        n00b_json_node_t *vi = n00b_json_array_get(viol, i);
        assert(vi != nullptr);
        assert(n00b_json_is_object(vi));
        assert(!json_object_has_key(vi, "severity"));
    }
    assert(strstr(out, "\"severity\"") == nullptr);

    printf("  [PASS] fixture_null json (exit=1, violations=%zu, no severity)\n",
           viol_len);
}

static void
test_fixture_nullptr_json(void)
{
    int argc = 0;
    n00b_string_t **argv = build_argv6(
        n00b_string_from_cstr("n00b-audit"),
        n00b_string_from_cstr("--guidance"),
        fixture_path("guidance_phase4.bnf"),
        n00b_string_from_cstr("--format"),
        n00b_string_from_cstr("json"),
        fixture_path("fixture_nullptr.c"),
        &argc);

    capture_t cap;
    capture_begin(&cap);
    n00b_result_t(int) r = n00b_audit_run_cli(argc, argv);
    static char out[CAPTURE_BUF_SIZE];
    static char err[CAPTURE_BUF_SIZE];
    capture_end(&cap, out, sizeof(out), err, sizeof(err));

    if (n00b_result_is_err(r)) {
        fprintf(stderr,
                "  fixture_nullptr run_cli returned err code=%d\n",
                n00b_result_get_err(r));
        fprintf(stderr, "  captured stderr: %s\n", err);
    }
    assert(n00b_result_is_ok(r));
    int code = n00b_result_get(r);
    if (code != 0) {
        fprintf(stderr, "  expected exit-int 0 (no violations), got %d\n",
                code);
        fprintf(stderr, "  captured stdout: %s\n", out);
        fprintf(stderr, "  captured stderr: %s\n", err);
    }
    assert(code == 0);
    assert(strlen(out) > 0);

    /* Round-trip parse the captured JSON — even with zero violations
     * the renderer still emits a well-formed envelope. */
    const char *jerr = nullptr;
    n00b_json_node_t *root = n00b_json_parse(out, strlen(out), &jerr);
    if (!root) {
        fprintf(stderr, "  JSON parse failed: %s\n",
                jerr ? jerr : "(no message)");
        fprintf(stderr, "  captured stdout: %s\n", out);
    }
    assert(root != nullptr);
    assert(n00b_json_is_object(root));

    n00b_json_node_t *viol = json_object_get(root, "violations");
    assert(viol != nullptr);
    assert(n00b_json_is_array(viol));
    assert(n00b_json_array_len(viol) == 0);

    n00b_json_node_t *summary = json_object_get(root, "summary");
    assert(summary != nullptr);
    assert(n00b_json_is_object(summary));
    n00b_json_node_t *ec = json_object_get(summary, "error_count");
    assert(ec != nullptr);
    assert(n00b_json_is_int(ec));
    assert(n00b_json_as_i64(ec) == 0);

    /* D-005 carveout: no `severity` key anywhere. */
    assert(!json_object_has_key(root, "severity"));
    assert(!json_object_has_key(summary, "severity"));
    assert(strstr(out, "\"severity\"") == nullptr);

    /* Zero-violations envelope carries no "rewrite" anywhere either. */
    assert(strstr(out, "\"rewrite\"") == nullptr);

    printf("  [PASS] fixture_nullptr json (exit=0, violations=0, no severity)\n");
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    test_fixture_null_json();
    test_fixture_nullptr_json();

    printf("All n00b-audit Phase 5 JSON regression checks passed.\n");
    return 0;
}

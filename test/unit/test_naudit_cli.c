/*
 * WP-001 Phase 4 regression test — CLI driver (terminal output).
 *
 * Exercises the library-shaped entry `n00b_audit_run_cli(argc, argv)`
 * directly (no subproc) against three cases:
 *
 *   1. fixture_null.c + guidance_phase4.bnf → ok-int 1, captured
 *      stdout contains the rule id `n00b.s2_1.null`, at least one
 *      captured line begins with `  | ` (the good-example prefix).
 *   2. fixture_nullptr.c + guidance_phase4.bnf → ok-int 0,
 *      captured stdout is empty.
 *   3. <fixture_dir>/does_not_exist.c → ok-int 2, captured stderr
 *      is non-empty.
 *
 * Capture mechanism: POSIX `pipe()` + `dup2()` around fd 1 (stdout)
 * and fd 2 (stderr). libn00b's fd_writer holds the integer fd
 * number and writes via the POSIX `write()` syscall, so post-dup2
 * writes land on our pipe read-end. The relaxed test-file
 * convention (NCC.md "NO LIBC ALLOWED" exemption for test sources)
 * makes libc `<unistd.h>` / `<assert.h>` / `<stdio.h>` /
 * `<string.h>` fair game for harness scaffolding.
 *
 * Bootstrap shape mirrors test/unit/test_audit_engine.c per the
 * relaxed test convention: main(argc, argv) + n00b_init_simple
 * first thing, fixture-path discovery via the
 * N00B_AUDIT_TEST_FIXTURE_DIR macro (no hardcoded paths in C
 * source — set by test/meson.build).
 *
 * Per project DECISIONS.md D-005, there is no `severity` field
 * anywhere in this test — no assertion mentions severity, no
 * field is checked on n00b_audit_violation_t for severity.
 *
 * The fixture .c files contain `NULL` and `nullptr` as PARSE-TARGET
 * input; the n00b-api-guidelines § 2.1 NULL→nullptr rule does NOT
 * apply to them.
 */

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test_portability.h"

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"

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
/* Stdout/stderr capture via POSIX pipe + dup2.                 */
/* ------------------------------------------------------------ */

typedef struct {
    int  saved_stdout;
    int  saved_stderr;
    int  stdout_pipe[2]; /* [0]=read, [1]=write */
    int  stderr_pipe[2];
} capture_t;

/*
 * Install pipe-backed redirects for fd 1 and fd 2. Each pipe's
 * write end is dup2'd onto the corresponding stdio fd, then closed
 * (the dup2 already gave it a new fd). The read end stays open in
 * the test process so we can read back the captured bytes after
 * the call.
 *
 * The original fd 1 / fd 2 are dup'd into `saved_*` so the test
 * can restore them after each case (otherwise the next case's
 * setup would clobber).
 */
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

    /* Make the read ends non-blocking so capture_end's drain can
     * terminate cleanly even if there's no data. */
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

/*
 * Read all available bytes from the capture pipes into the supplied
 * buffers (which must each be at least CAPTURE_BUF_SIZE bytes), then
 * restore the saved fd 1 / fd 2. The output buffers are
 * NUL-terminated.
 */
static void
capture_end(capture_t *cap, char *stdout_out, size_t stdout_cap,
            char *stderr_out, size_t stderr_cap)
{
    /* Restore original fds first so any subsequent test output is
     * visible to the parent meson runner. */
    dup2(cap->saved_stdout, 1);
    dup2(cap->saved_stderr, 2);
    close(cap->saved_stdout);
    close(cap->saved_stderr);

    /* Drain. */
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
/* Test cases.                                                  */
/* ------------------------------------------------------------ */

static n00b_string_t **
build_argv4(n00b_string_t *prog, n00b_string_t *flag, n00b_string_t *val,
            n00b_string_t *positional, int *argc_out)
{
    n00b_string_t **argv = (n00b_string_t **)n00b_alloc_array(
        n00b_string_t *, 5);
    argv[0] = prog;
    argv[1] = flag;
    argv[2] = val;
    argv[3] = positional;
    argv[4] = nullptr;
    *argc_out = 4;
    return argv;
}

static void
join_path(char *out, size_t out_cap, const char *dir, const char *name)
{
    int n = snprintf(out, out_cap, "%s/%s", dir, name);
    assert(n > 0 && (size_t)n < out_cap);
}

static void
write_text_file(const char *path, const char *text)
{
    FILE *fp = fopen(path, "w");
    assert(fp != nullptr);
    assert(fputs(text, fp) >= 0);
    assert(fclose(fp) == 0);
}

static int
run_cli_from_dir(const char *cwd,
                 const char *guidance,
                 const char *target,
                 char       *out,
                 size_t      out_cap,
                 char       *err,
                 size_t      err_cap)
{
    char saved_cwd[1024];
    assert(getcwd(saved_cwd, sizeof(saved_cwd)) != nullptr);
    assert(chdir(cwd) == 0);

    int argc = 0;
    n00b_string_t **argv = build_argv4(
        n00b_string_from_cstr("n00b-audit"),
        n00b_string_from_cstr("--guidance"),
        n00b_string_from_cstr(guidance),
        n00b_string_from_cstr(target),
        &argc);

    capture_t cap;
    capture_begin(&cap);
    n00b_result_t(int) r = n00b_audit_run_cli(argc, argv);
    capture_end(&cap, out, out_cap, err, err_cap);

    assert(chdir(saved_cwd) == 0);
    assert(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static void
test_fixture_null(void)
{
    int argc = 0;
    n00b_string_t **argv = build_argv4(
        n00b_string_from_cstr("n00b-audit"),
        n00b_string_from_cstr("--guidance"),
        fixture_path("guidance_phase4.bnf"),
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

    /* Header line must carry the rule id. */
    assert(strstr(out, "n00b.s2_1.null") != nullptr);

    /* At least one captured line begins with `  | ` (the
     * good-example prefix). Search line-by-line — `strstr` for
     * `\n  | ` catches non-leading lines; check the leading line
     * separately for the case where the block prefix opens the
     * whole capture (it won't for terminal output, but be
     * defensive). */
    bool found_prefix = (strstr(out, "\n  | ") != nullptr)
                        || (strncmp(out, "  | ", 4) == 0);
    if (!found_prefix) {
        fprintf(stderr, "  expected `  | ` prefixed line in stdout; got:\n%s\n",
                out);
    }
    assert(found_prefix);

    /* WP-007 Phase 2: the terminal renderer must emit a "suggested
     * fix: nullptr" line for the n00b.s2_1.null rule (the
     * guidance_phase4.bnf fixture carries a rewrite block on this
     * rule). */
    if (strstr(out, "suggested fix: nullptr") == nullptr) {
        fprintf(stderr,
                "  expected `suggested fix: nullptr` in stdout; got:\n%s\n",
                out);
    }
    assert(strstr(out, "suggested fix: nullptr") != nullptr);

    printf("  [PASS] fixture_null (exit=1, stdout=%zu bytes)\n",
           strlen(out));
}

static void
test_fixture_nullptr(void)
{
    int argc = 0;
    n00b_string_t **argv = build_argv4(
        n00b_string_from_cstr("n00b-audit"),
        n00b_string_from_cstr("--guidance"),
        fixture_path("guidance_phase4.bnf"),
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
    assert(strlen(out) == 0);

    printf("  [PASS] fixture_nullptr (exit=0, stdout empty)\n");
}

static void
test_relative_guidance_path_loads_current_directory_rules(void)
{
    char root_template[] = "/tmp/n00b-naudit-cache-XXXXXX";
    char *root = mkdtemp(root_template);
    assert(root != nullptr);

    char dir1[1024];
    char dir2[1024];
    join_path(dir1, sizeof(dir1), root, "one");
    join_path(dir2, sizeof(dir2), root, "two");
    assert(mkdir(dir1, 0700) == 0);
    assert(mkdir(dir2, 0700) == 0);

    char path[1024];
    join_path(path, sizeof(path), dir1, "audit-rules.bnf");
    write_text_file(path,
        "@schema_version 1\n"
        "@project cache-one\n"
        "@description first relative-path cache fixture\n"
        "@source_doc cache-one\n"
        "@dependencies\n"
        "\n"
        "@rule cache.first.null\n"
        "@title first guidance\n"
        "@section cache\n"
        "@violation_nt cache_v_null\n"
        "@rationale first\n"
        "@bad int *p = NULL;\n"
        "@good int *p = nullptr;\n"
        "@guidance first\n"
        "\n"
        "<cache_v_null> ::= %\"NULL\"\n"
        "<provided_identifier> ::= <cache_v_null>\n");
    join_path(path, sizeof(path), dir1, "target.c");
    write_text_file(path,
        "int\n"
        "main(void)\n"
        "{\n"
        "    int *p = NULL;\n"
        "    return p == NULL ? 0 : 1;\n"
        "}\n");

    join_path(path, sizeof(path), dir2, "audit-rules.bnf");
    write_text_file(path,
        "@schema_version 1\n"
        "@project cache-two\n"
        "@description second relative-path cache fixture\n"
        "@source_doc cache-two\n"
        "@dependencies\n"
        "\n"
        "@rule cache.second.nullptr\n"
        "@title second guidance\n"
        "@section cache\n"
        "@violation_nt cache_v_nullptr\n"
        "@rationale second\n"
        "@bad int *p = nullptr;\n"
        "@good int *p = 0;\n"
        "@guidance second\n"
        "\n"
        "<cache_v_nullptr> ::= %\"nullptr\"\n"
        "<provided_identifier> ::= <cache_v_nullptr>\n");
    join_path(path, sizeof(path), dir2, "target.c");
    write_text_file(path,
        "int\n"
        "main(void)\n"
        "{\n"
        "    int *p = nullptr;\n"
        "    return p == nullptr ? 0 : 1;\n"
        "}\n");

    static char out[CAPTURE_BUF_SIZE];
    static char err[CAPTURE_BUF_SIZE];
    int code = run_cli_from_dir(dir1,
                                "audit-rules.bnf",
                                "target.c",
                                out,
                                sizeof(out),
                                err,
                                sizeof(err));
    assert(code == 1);
    assert(strstr(out, "cache.first.null") != nullptr);

    code = run_cli_from_dir(dir2,
                            "audit-rules.bnf",
                            "target.c",
                            out,
                            sizeof(out),
                            err,
                            sizeof(err));
    if (code != 1 || strstr(out, "cache.second.nullptr") == nullptr) {
        fprintf(stderr,
                "  expected second relative guidance rule; code=%d stdout=%s stderr=%s\n",
                code,
                out,
                err);
    }
    assert(code == 1);
    assert(strstr(out, "cache.second.nullptr") != nullptr);

    char file[1024];
    join_path(file, sizeof(file), dir1, "audit-rules.bnf");
    unlink(file);
    join_path(file, sizeof(file), dir1, "target.c");
    unlink(file);
    join_path(file, sizeof(file), dir2, "audit-rules.bnf");
    unlink(file);
    join_path(file, sizeof(file), dir2, "target.c");
    unlink(file);
    rmdir(dir1);
    rmdir(dir2);
    rmdir(root);

    printf("  [PASS] relative guidance path loads current directory rules\n");
}

static void
test_missing_target(void)
{
    int argc = 0;
    n00b_string_t **argv = build_argv4(
        n00b_string_from_cstr("n00b-audit"),
        n00b_string_from_cstr("--guidance"),
        fixture_path("guidance_phase4.bnf"),
        fixture_path("does_not_exist.c"),
        &argc);

    capture_t cap;
    capture_begin(&cap);
    n00b_result_t(int) r = n00b_audit_run_cli(argc, argv);
    static char out[CAPTURE_BUF_SIZE];
    static char err[CAPTURE_BUF_SIZE];
    capture_end(&cap, out, sizeof(out), err, sizeof(err));

    assert(n00b_result_is_ok(r));
    int code = n00b_result_get(r);
    if (code != 2) {
        fprintf(stderr,
                "  expected exit-int 2 (internal err), got %d\n", code);
        fprintf(stderr, "  captured stdout: %s\n", out);
        fprintf(stderr, "  captured stderr: %s\n", err);
    }
    assert(code == 2);
    assert(strlen(err) > 0);

    printf("  [PASS] missing target (exit=2, stderr present)\n");
}

/*
 * Regression: a guidance file whose `@violation_nt` references a
 * non-existent NT used to send the parser into a pathological
 * loop / SIGSEGV. The engine now validates each rule's
 * violation_nt resolves to an NT in the merged grammar and fails
 * fast with GUIDANCE_SCHEMA. The CLI surfaces this as exit-int 2.
 */
static void
test_dangling_violation_nt(void)
{
    int argc = 0;
    n00b_string_t **argv = build_argv4(
        n00b_string_from_cstr("n00b-audit"),
        n00b_string_from_cstr("--guidance"),
        fixture_path("guidance_ok.bnf"),
        fixture_path("fixture_null.c"),
        &argc);

    capture_t cap;
    capture_begin(&cap);
    n00b_result_t(int) r = n00b_audit_run_cli(argc, argv);
    static char out[CAPTURE_BUF_SIZE];
    static char err[CAPTURE_BUF_SIZE];
    capture_end(&cap, out, sizeof(out), err, sizeof(err));

    assert(n00b_result_is_ok(r));
    int code = n00b_result_get(r);
    if (code != 2) {
        fprintf(stderr,
                "  expected exit-int 2 (schema), got %d\n", code);
        fprintf(stderr, "  captured stdout: %s\n", out);
        fprintf(stderr, "  captured stderr: %s\n", err);
    }
    assert(code == 2);
    assert(strlen(err) > 0);

    printf("  [PASS] dangling violation_nt (exit=2, stderr present)\n");
}

static void
test_err_str_cli_codes(void)
{
    /* Round-trip every CLI_* code through err_str. */
    assert(n00b_audit_err_str(N00B_AUDIT_ERR_CLI_ARGS)     != nullptr);
    assert(n00b_audit_err_str(N00B_AUDIT_ERR_CLI_BAD_ARGS) != nullptr);
    assert(n00b_audit_err_str(N00B_AUDIT_ERR_CLI_RENDER)   != nullptr);
    printf("  [PASS] err_str CLI codes\n");
}

/* ------------------------------------------------------------ */
/* WP-007 Phase 2 — --fix CLI flag end-to-end.                 */
/* ------------------------------------------------------------ */

static n00b_string_t **
build_argv5(n00b_string_t *prog, n00b_string_t *g_flag, n00b_string_t *g_val,
            n00b_string_t *fix_flag, n00b_string_t *positional,
            int *argc_out)
{
    n00b_string_t **argv = (n00b_string_t **)n00b_alloc_array(
        n00b_string_t *, 6);
    argv[0] = prog;
    argv[1] = g_flag;
    argv[2] = g_val;
    argv[3] = fix_flag;
    argv[4] = positional;
    argv[5] = nullptr;
    *argc_out = 5;
    return argv;
}

/* Copy a file via POSIX read/write (the relaxed test-file convention
 * permits libc here). Returns 0 on success. */
static int
copy_file(const char *src, const char *dst)
{
    int sfd = open(src, O_RDONLY);
    if (sfd < 0) {
        return -1;
    }
    int dfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dfd < 0) {
        close(sfd);
        return -1;
    }
    char    buf[8192];
    ssize_t n;
    while ((n = read(sfd, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(dfd, buf + off, (size_t)(n - off));
            if (w <= 0) {
                close(sfd); close(dfd);
                return -1;
            }
            off += w;
        }
    }
    close(sfd);
    close(dfd);
    return (int)n;
}

/* Slurp a file into a function-local static buffer; sets *out_len.
 * NUL-terminated. Not reentrant — successive calls overwrite the
 * same backing storage, so the caller must consume the result
 * (asserts, memcmp, etc.) before calling slurp() again. */
static char *
slurp(const char *path, size_t *out_len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return nullptr;
    }
    static char buf[64 * 1024];
    size_t      off = 0;
    ssize_t     n;
    while ((n = read(fd, buf + off, sizeof(buf) - 1 - off)) > 0) {
        off += (size_t)n;
        if (off >= sizeof(buf) - 1) break;
    }
    close(fd);
    buf[off]  = '\0';
    *out_len  = off;
    return buf;
}

static void
test_fix_flag(void)
{
    /*
     * Copy fixture_null.c into /tmp/n00b_audit_fix_smoke.c and invoke
     * naudit --fix against the copy. Asserts:
     *   - exit code 0,
     *   - <copy>.bak exists with the original content,
     *   - <copy> now contains the rewrite (NULL → nullptr),
     *   - re-running audit without --fix produces zero violations.
     */
    const char *tmp_path     = "/tmp/n00b_audit_fix_smoke.c";
    const char *bak_path     = "/tmp/n00b_audit_fix_smoke.c.bak";
    unlink(tmp_path);
    unlink(bak_path);

    /* Materialize the source-of-truth fixture path through fixture_path. */
    n00b_string_t *fixture_src = fixture_path("fixture_null.c");
    int rc = copy_file(fixture_src->data, tmp_path);
    assert(rc == 0);

    int argc = 0;
    n00b_string_t **argv = build_argv5(
        n00b_string_from_cstr("n00b-audit"),
        n00b_string_from_cstr("--guidance"),
        fixture_path("guidance_phase4.bnf"),
        n00b_string_from_cstr("--fix"),
        n00b_string_from_cstr(tmp_path),
        &argc);

    capture_t cap;
    capture_begin(&cap);
    n00b_result_t(int) r = n00b_audit_run_cli(argc, argv);
    static char out[CAPTURE_BUF_SIZE];
    static char err[CAPTURE_BUF_SIZE];
    capture_end(&cap, out, sizeof(out), err, sizeof(err));

    if (n00b_result_is_err(r)) {
        fprintf(stderr,
                "  --fix run_cli returned err code=%d\n  stderr: %s\n",
                n00b_result_get_err(r), err);
    }
    assert(n00b_result_is_ok(r));
    int code = n00b_result_get(r);
    if (code != 0) {
        fprintf(stderr, "  expected exit-int 0, got %d\n  stderr: %s\n",
                code, err);
    }
    assert(code == 0);

    /* `.bak` exists with the original NULL content. */
    size_t bak_len = 0;
    char  *bak     = slurp(bak_path, &bak_len);
    assert(bak != nullptr);
    assert(strstr(bak, "= NULL;") != nullptr);
    /* Updated file has nullptr now. */
    size_t fix_len = 0;
    char  *fix     = slurp(tmp_path, &fix_len);
    assert(fix != nullptr);
    assert(strstr(fix, "= nullptr;") != nullptr);
    assert(strstr(fix, "= NULL;") == nullptr);

    /* Re-run without --fix; expect clean (exit 0, empty stdout). */
    int argc2 = 0;
    n00b_string_t **argv2 = build_argv4(
        n00b_string_from_cstr("n00b-audit"),
        n00b_string_from_cstr("--guidance"),
        fixture_path("guidance_phase4.bnf"),
        n00b_string_from_cstr(tmp_path),
        &argc2);
    capture_t cap2;
    capture_begin(&cap2);
    n00b_result_t(int) r2 = n00b_audit_run_cli(argc2, argv2);
    static char out2[CAPTURE_BUF_SIZE];
    static char err2[CAPTURE_BUF_SIZE];
    capture_end(&cap2, out2, sizeof(out2), err2, sizeof(err2));

    assert(n00b_result_is_ok(r2));
    int code2 = n00b_result_get(r2);
    if (code2 != 0) {
        fprintf(stderr,
                "  re-run after --fix: expected exit 0, got %d\n"
                "  stdout: %s\n  stderr: %s\n",
                code2, out2, err2);
    }
    assert(code2 == 0);

    /* Cleanup. */
    unlink(tmp_path);
    unlink(bak_path);

    printf("  [PASS] --fix end-to-end (file updated, .bak created, re-run clean)\n");
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    test_err_str_cli_codes();
    test_fixture_null();
    test_fixture_nullptr();
    test_relative_guidance_path_loads_current_directory_rules();
    test_missing_target();
    test_dangling_violation_nt();
    test_fix_flag();

    printf("All n00b-audit Phase 4 CLI regression checks passed.\n");
    return 0;
}

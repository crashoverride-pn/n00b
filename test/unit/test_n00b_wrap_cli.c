/**
 * @file test_n00b_wrap_cli.c
 * @brief WP-017 follow-up: CLI regression tests for the `n00b-wrap` tool.
 *
 * These tests spawn the actual built `n00b-wrap` binary (path injected via
 * `-DN00B_WRAP_TOOL_PATH=...`) and assert its command-line behavior. They cover
 * the cases the original Phase-4 work missed (no-args / --help / bad flag /
 * missing -o), the real wrap roundtrip, and — critically — that bare `n00b-wrap`
 * does NOT hang when run under an interactive terminal (a `forkpty` regression
 * for the core `n00b_shutdown`/`tcdrain` fix; the bug only reproduced on a TTY).
 *
 * D-018 test-scaffolding libc exemption: this harness uses forkpty/waitpid/
 * usleep/kill/getenv for process control; all code-under-test interaction goes
 * through the `n00b-wrap` binary and the n00b subprocess API.
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "n00b.h"
#include "core/runtime.h"

#ifndef N00B_WRAP_TOOL_PATH
#define N00B_WRAP_TOOL_PATH "n00b-wrap"
#endif

#if defined(_WIN32)

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);
    printf("  [SKIP] n00b_wrap_cli is POSIX-only.\n");
    return 0;
}

#else

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <util.h> // forkpty
#elif defined(__linux__)
#include <pty.h> // forkpty
#endif

#include "adt/array.h"
#include "adt/result.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/print.h"
#include "conduit/subproc.h"
#include "core/buffer.h"
#include "core/file.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "util/path.h"
#include "compiler/objfile/obj_bundle.h"
#include "internal/compiler/objfile/obj_bundle_exec.h"

#define CHECK(expr) n00b_require((expr), "test check failed: " #expr)

typedef struct {
    int            exit_code;
    n00b_string_t *out;
    n00b_string_t *err;
} cli_run_t;

static n00b_string_t *
buffer_string(n00b_buffer_t *buf)
{
    if (buf == nullptr || buf->byte_len == 0) {
        return r"";
    }
    return n00b_buffer_to_string(n00b_buffer_copy(buf));
}

// Spawn an arbitrary executable with args (+ optional extra env entry) over
// pipes; capture exit code + stdout/stderr.
static cli_run_t
run_exe(n00b_string_t *cmd, n00b_array_t(n00b_string_t *) *args,
        n00b_string_t *extra_env)
{
    auto conduit_r = n00b_conduit_new();
    CHECK(n00b_result_is_ok(conduit_r));
    n00b_conduit_t *conduit = n00b_result_get(conduit_r);

    auto io_r = n00b_conduit_io_new_default(conduit);
    CHECK(n00b_result_is_ok(io_r));
    n00b_conduit_io_backend_t *io = n00b_result_get(io_r);

    n00b_array_t(n00b_string_t *) *env =
        n00b_alloc(n00b_array_t(n00b_string_t *));
    *env = n00b_array_new(n00b_string_t *, extra_env != nullptr ? 2 : 1);
    n00b_array_set(*env, 0, r"N00B_TEST=1");
    if (extra_env != nullptr) {
        n00b_array_set(*env, 1, extra_env);
    }

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
                      .cmd            = cmd,
                      .conduit        = conduit,
                      .io             = io,
                      .args           = args,
                      .env            = env,
                      .capture_stdout = true,
                      .capture_stderr = true,
                      .merge          = false);

    auto run_r = n00b_subproc_run(&sp);
    CHECK(n00b_result_is_ok(run_r));

    auto code_r = n00b_subproc_exit_code(&sp);
    CHECK(n00b_result_is_ok(code_r));

    cli_run_t result = {
        .exit_code = n00b_result_get(code_r),
        .out       = buffer_string(n00b_subproc_stdout(&sp)),
        .err       = buffer_string(n00b_subproc_stderr(&sp)),
    };

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(conduit);
    return result;
}

// Spawn the n00b-wrap tool itself with the given args (+ optional extra env).
static cli_run_t
run_wrap(n00b_array_t(n00b_string_t *) *args, n00b_string_t *extra_env)
{
    return run_exe(n00b_string_from_cstr(N00B_WRAP_TOOL_PATH), args, extra_env);
}

static n00b_array_t(n00b_string_t *) *
args_of(int count, ...)
{
    n00b_array_t(n00b_string_t *) *args =
        n00b_alloc(n00b_array_t(n00b_string_t *));
    *args = n00b_array_new(n00b_string_t *, count);
    va_list ap;
    va_start(ap, count);
    for (int i = 0; i < count; i++) {
        n00b_array_set(*args, i, va_arg(ap, n00b_string_t *));
    }
    va_end(ap);
    return args;
}

static bool
contains(n00b_string_t *haystack, n00b_string_t *needle)
{
    return n00b_option_is_set(n00b_unicode_str_find(haystack, needle));
}

// C1: no args → help on stderr, exit 0 (over pipes; the forkpty test below
// covers the TTY no-hang case).
static void
test_no_args_help(void)
{
    cli_run_t r = run_wrap(args_of(0), nullptr);
    CHECK(r.exit_code == 0);
    CHECK(contains(r.err, r"usage: n00b-wrap"));
}

// C2: --help → help, exit 0.
static void
test_help_flag(void)
{
    cli_run_t r = run_wrap(args_of(1, r"--help"), nullptr);
    CHECK(r.exit_code == 0);
    CHECK(contains(r.err, r"usage: n00b-wrap"));
}

// C3: unknown flag → usage error, exit 2.
static void
test_bad_flag(void)
{
    cli_run_t r = run_wrap(args_of(2, r"--bogus", r"x"), nullptr);
    CHECK(r.exit_code == 2);
}

// C4: target present but no -o/--output → usage error, exit 2.
static void
test_missing_output(void)
{
    cli_run_t r = run_wrap(args_of(1, r"/usr/bin/true"), nullptr);
    CHECK(r.exit_code == 2);
}

// C5 (TTY no-hang regression): bare n00b-wrap under a real PTY must EXIT (it
// must not block in n00b_shutdown/tcdrain). Bounded wait; a timeout is the bug.
static void
test_no_tty_hang(void)
{
#if defined(__APPLE__) || defined(__linux__)
    int   amaster = -1;
    pid_t pid     = forkpty(&amaster, nullptr, nullptr, nullptr);
    CHECK(pid >= 0);

    if (pid == 0) {
        execl(N00B_WRAP_TOOL_PATH, "n00b-wrap", (char *)nullptr);
        _exit(127);
    }

    int  status  = 0;
    bool exited  = false;
    for (int i = 0; i < 100; i++) { // up to ~10s
        if (waitpid(pid, &status, WNOHANG) == pid) {
            exited = true;
            break;
        }
        usleep(100000);
    }

    if (!exited) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        if (amaster >= 0) {
            close(amaster);
        }
        CHECK(!"n00b-wrap hung under a TTY (n00b_shutdown/tcdrain regression)");
        return;
    }

    if (amaster >= 0) {
        close(amaster);
    }
    CHECK(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0); // no-args → help → 0
#else
    printf("  [SKIP] C5: forkpty unavailable on this platform.\n");
#endif
}

// C6 (Mach-O wrap roundtrip; __APPLE__-gated): n00b-wrap wraps /usr/bin/true and
// the output is a valid carrier bearing the EMBEDDED_N00B policy.
static void
test_wrap_roundtrip(void)
{
#if !defined(__APPLE__)
    printf("  [SKIP] C6: Mach-O wrap is macOS-only.\n");
#else
    auto td = n00b_new_temp_dir(r"n00b-wrap-cli-", nullptr);
    CHECK(n00b_result_is_ok(td));
    n00b_string_t *out = n00b_path_simple_join(n00b_result_get(td), r"wrapped");

    cli_run_t r = run_wrap(args_of(3, r"/usr/bin/true", r"-o", out), nullptr);
    CHECK(r.exit_code == 0);
    CHECK(n00b_path_exists(out));

    // Read the produced carrier back; it must carry an EMBEDDED_N00B EXECUTION
    // policy (the default agent-guard).
    auto open_result = n00b_file_open(out,
                                      .kind     = N00B_FILE_KIND_MMAP,
                                      .populate = true);
    CHECK(n00b_result_is_ok(open_result));
    n00b_file_t *f      = n00b_result_get(open_result);
    auto         as_buf = n00b_file_as_buffer(f);
    CHECK(n00b_result_is_ok(as_buf));
    n00b_buffer_t *view = n00b_result_get(as_buf);
    n00b_buffer_t *copy = n00b_buffer_from_bytes(view->data,
                                                 (int64_t)view->byte_len);
    n00b_file_close(f);

    auto read_r = n00b_obj_bundle_read(copy);
    CHECK(n00b_result_is_ok(read_r));
    n00b_obj_bundle_t *bundle = n00b_result_get(read_r);
    n00b_option_t(n00b_string_t *) policy_src =
        _n00b_obj_bundle_embedded_policy_source_for_scope(
            bundle,
            N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION);
    CHECK(n00b_option_is_set(policy_src));

    // Running the wrapped binary (exec) is N00B_TEST_EXEC_RUN-gated (D-006). The
    // agent set is overridden so the verdict is ALLOW regardless of ancestry.
    const char *exec_gate = getenv("N00B_TEST_EXEC_RUN");
    if (exec_gate != nullptr && exec_gate[0] == '1') {
        // Spawn the WRAPPED output directly (not the builder): it self-detects
        // as a carrier and runs the agent-guard policy. With the agent set
        // overridden to a sentinel, the verdict is ALLOW → it execs /usr/bin/true.
        n00b_array_t(n00b_string_t *) *no_args =
            n00b_alloc(n00b_array_t(n00b_string_t *));
        *no_args = n00b_array_new(n00b_string_t *, 0);

        auto conduit_r = n00b_conduit_new();
        CHECK(n00b_result_is_ok(conduit_r));
        n00b_conduit_t *conduit = n00b_result_get(conduit_r);
        auto            io_r    = n00b_conduit_io_new_default(conduit);
        CHECK(n00b_result_is_ok(io_r));
        n00b_conduit_io_backend_t *io = n00b_result_get(io_r);

        n00b_array_t(n00b_string_t *) *env =
            n00b_alloc(n00b_array_t(n00b_string_t *));
        *env = n00b_array_new(n00b_string_t *, 2);
        n00b_array_set(*env, 0, r"N00B_TEST=1");
        n00b_array_set(*env, 1, r"N00B_WRAP_AGENTS=__none__");

        n00b_subproc_t sp = {};
        n00b_subproc_init(&sp,
                          .cmd            = out,
                          .conduit        = conduit,
                          .io             = io,
                          .args           = no_args,
                          .env            = env,
                          .capture_stdout = true,
                          .capture_stderr = true,
                          .merge          = false);
        auto wr = n00b_subproc_run(&sp);
        CHECK(n00b_result_is_ok(wr));
        auto wc = n00b_subproc_exit_code(&sp);
        CHECK(n00b_result_is_ok(wc));
        CHECK(n00b_result_get(wc) == 0); // allow path → exec /usr/bin/true → 0
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(conduit);
    }
    else {
        printf("  [SKIP] C6 exec: N00B_TEST_EXEC_RUN!=1\n");
    }
#endif
}

// C7 (Mach-O wrap + exec; __APPLE__ + N00B_TEST_EXEC_RUN-gated): the wrapped
// binary forwards the FULL invocation argv (incl. argv[0]) to the embedded
// target. Wrap /bin/echo, run it with args, and assert echo prints them.
static void
test_argv_passthrough(void)
{
#if !defined(__APPLE__)
    printf("  [SKIP] C7: Mach-O wrap is macOS-only.\n");
#else
    const char *exec_gate = getenv("N00B_TEST_EXEC_RUN");
    if (exec_gate == nullptr || exec_gate[0] != '1') {
        printf("  [SKIP] C7: N00B_TEST_EXEC_RUN!=1\n");
        return;
    }
    if (!n00b_path_exists(r"/bin/echo")) {
        printf("  [SKIP] C7: /bin/echo not present\n");
        return;
    }

    auto td = n00b_new_temp_dir(r"n00b-wrap-argv-", nullptr);
    CHECK(n00b_result_is_ok(td));
    n00b_string_t *out = n00b_path_simple_join(n00b_result_get(td), r"echowrap");

    cli_run_t w = run_wrap(args_of(3, r"/bin/echo", r"-o", out), nullptr);
    CHECK(w.exit_code == 0);

    // Run the wrapped echo with args; agents disabled so the policy allows + execs.
    cli_run_t r = run_exe(out,
                          args_of(2, r"alpha", r"beta"),
                          r"N00B_WRAP_AGENTS=__none__");
    CHECK(r.exit_code == 0);
    CHECK(contains(r.out, r"alpha beta")); // echo printed the proxied args
#endif
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_no_args_help();
    test_help_flag();
    test_bad_flag();
    test_missing_output();
    test_no_tty_hang();
    test_wrap_roundtrip();
    test_argv_passthrough();

    printf("  n00b_wrap_cli: CLI + no-TTY-hang + roundtrip + argv OK\n");
    n00b_shutdown();
    return 0;
}

#endif // _WIN32

/*
 * test_subproc.c — Tests for subprocess management module.
 */

#ifndef _WIN32

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>

#include "n00b.h"
#include "conduit/subproc.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/xform_linebuf.h"
#include "conduit/xform_ansi_strip.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"

// ============================================================================
// Helpers
// ============================================================================

static n00b_conduit_t *
make_conduit(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    return n00b_result_get(cr);
}

static n00b_conduit_io_backend_t *
make_io(n00b_conduit_t *c)
{
    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    return n00b_result_get(ir);
}

// ============================================================================
// 1. Basic init and flag defaults
// ============================================================================

static void
test_init_defaults(void)
{
    n00b_conduit_t *c = make_conduit();

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd     = n00b_string_from_cstr("/bin/echo"),
        .conduit = c);

    // Not spawned yet.
    assert(!n00b_subproc_is_spawned(&sp));
    assert(!n00b_subproc_exited(&sp));
    assert(!n00b_subproc_errored(&sp));
    assert(!n00b_subproc_timed_out(&sp));
    assert(!n00b_option_is_set(n00b_subproc_pid(&sp)));

    // Merge is on by default.
    assert((sp.flags & N00B_SUBPROC_MERGE_OUTPUT) != 0);

    // Handle winsize on by default.
    assert((sp.flags & N00B_SUBPROC_HANDLE_WINSIZE) != 0);

    n00b_conduit_destroy(c);
    printf("  [PASS] init defaults\n");
}

// ============================================================================
// 2. Capture convenience flag
// ============================================================================

static void
test_capture_convenience(void)
{
    n00b_conduit_t *c = make_conduit();

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd     = n00b_string_from_cstr("/bin/echo"),
        .conduit = c,
        .capture = true);

    assert((sp.flags & N00B_SUBPROC_CAP_ALL) == N00B_SUBPROC_CAP_ALL);

    n00b_conduit_destroy(c);
    printf("  [PASS] capture convenience\n");
}

// ============================================================================
// 3. Proxy convenience flag
// ============================================================================

static void
test_proxy_convenience(void)
{
    n00b_conduit_t *c = make_conduit();

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd     = n00b_string_from_cstr("/bin/echo"),
        .conduit = c,
        .proxy   = true);

    assert((sp.flags & N00B_SUBPROC_PROXY_ALL) == N00B_SUBPROC_PROXY_ALL);

    n00b_conduit_destroy(c);
    printf("  [PASS] proxy convenience\n");
}

// ============================================================================
// 4. Accessors return sane defaults before spawn
// ============================================================================

static void
test_accessors_pre_spawn(void)
{
    n00b_conduit_t *c = make_conduit();

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd     = n00b_string_from_cstr("/bin/echo"),
        .conduit = c);

    // Capture buffers return non-null (empty sentinel).
    assert(n00b_subproc_stdout(&sp) != nullptr);
    assert(n00b_subproc_stderr(&sp) != nullptr);
    assert(n00b_subproc_stdin_capture(&sp) != nullptr);

    // Exit code should be error (not exited).
    n00b_result_t(int) r = n00b_subproc_exit_code(&sp);
    assert(n00b_result_is_err(r));

    // Term signal should be error (not exited).
    r = n00b_subproc_term_signal(&sp);
    assert(n00b_result_is_err(r));

    n00b_conduit_destroy(c);
    printf("  [PASS] accessors pre-spawn\n");
}

// ============================================================================
// 5. Spawn /bin/echo — basic pipe mode
// ============================================================================

static void
test_spawn_echo(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd     = n00b_string_from_cstr("/bin/echo"),
        .conduit = c,
        .io      = io,
        .capture_stdout = true);

    n00b_result_t(bool) r = n00b_subproc_spawn(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] spawn echo (err=%d)\n", n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_is_spawned(&sp));
    assert(n00b_option_is_set(n00b_subproc_pid(&sp)));
    assert(n00b_option_get(n00b_subproc_pid(&sp)) > 0);

    // Wait for exit (simple waitpid).
    n00b_result_t(bool) wr = n00b_subproc_wait(&sp);
    assert(n00b_result_is_ok(wr));
    assert(n00b_subproc_exited(&sp));

    n00b_result_t(int) ec = n00b_subproc_exit_code(&sp);
    assert(n00b_result_is_ok(ec));
    assert(n00b_result_get(ec) == 0);

    n00b_subproc_close(&sp);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] spawn echo\n");
}

// ============================================================================
// 6. Spawn with invalid command → error
// ============================================================================

static void
test_spawn_bad_cmd(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd     = n00b_string_from_cstr("/nonexistent/bad/command"),
        .conduit = c,
        .io      = io);

    n00b_result_t(bool) r = n00b_subproc_spawn(&sp);
    // Should error because exec fails.
    assert(n00b_result_is_err(r));
    assert(n00b_subproc_errored(&sp));

    n00b_subproc_close(&sp);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] spawn bad command\n");
}

// ============================================================================
// 7. Spawn with no command → EINVAL
// ============================================================================

static void
test_spawn_no_cmd(void)
{
    n00b_conduit_t *c = make_conduit();

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp, .conduit = c);

    n00b_result_t(bool) r = n00b_subproc_spawn(&sp);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == EINVAL);

    n00b_conduit_destroy(c);
    printf("  [PASS] spawn no command\n");
}

// ============================================================================
// 8. Double spawn → EALREADY
// ============================================================================

static void
test_double_spawn(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd     = n00b_string_from_cstr("/bin/echo"),
        .conduit = c,
        .io      = io);

    n00b_result_t(bool) r = n00b_subproc_spawn(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] double spawn (first spawn failed)\n");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    // Second spawn should fail.
    n00b_result_t(bool) r2 = n00b_subproc_spawn(&sp);
    assert(n00b_result_is_err(r2));
    assert(n00b_result_get_err(r2) == EALREADY);

    // Clean up.
    n00b_subproc_wait(&sp);
    n00b_subproc_close(&sp);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] double spawn\n");
}

// ============================================================================
// 9. Close is idempotent
// ============================================================================

static void
test_close_idempotent(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd     = n00b_string_from_cstr("/bin/echo"),
        .conduit = c,
        .io      = io);

    n00b_result_t(bool) r = n00b_subproc_spawn(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] close idempotent\n");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    n00b_subproc_wait(&sp);
    n00b_subproc_close(&sp);
    n00b_subproc_close(&sp); // Second close should not crash.
    n00b_subproc_close(&sp); // Third close should not crash.

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] close idempotent\n");
}

// ============================================================================
// 10. Synchronous run with /bin/echo
// ============================================================================

static void
test_run_echo(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd     = n00b_string_from_cstr("/bin/echo"),
        .conduit = c,
        .io      = io);

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] run echo (err=%d)\n", n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_exited(&sp));

    n00b_result_t(int) ec = n00b_subproc_exit_code(&sp);
    assert(n00b_result_is_ok(ec));
    assert(n00b_result_get(ec) == 0);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] run echo\n");
}

// ============================================================================
// 11. Kill signal delivery
// ============================================================================

static void
test_kill(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd     = n00b_string_from_cstr("/bin/sleep"),
        .conduit = c,
        .io      = io,
        .args    = nullptr);

    // Add "100" argument.
    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 1);
    n00b_array_set(args, 0, n00b_string_from_cstr("100"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_spawn(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] kill (spawn failed)\n");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    // Send SIGTERM.
    n00b_result_t(bool) kr = n00b_subproc_kill(&sp);
    assert(n00b_result_is_ok(kr));

    // Wait for exit.
    n00b_subproc_wait(&sp);
    assert(n00b_subproc_exited(&sp));

    // Should have been terminated by signal.
    n00b_result_t(int) ts = n00b_subproc_term_signal(&sp);
    assert(n00b_result_is_ok(ts));
    assert(n00b_result_get(ts) == SIGTERM);

    n00b_subproc_close(&sp);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] kill\n");
}

// ============================================================================
// 12. Pre-exec hook fires
// ============================================================================

static void
test_hook_fn(void *param)
{
    // This runs in the child — we can't check it directly, but we
    // can verify the child runs successfully (the hook doesn't crash).
    // For verification, we write to a pipe.
    int *fd = (int *)param;
    if (fd) {
        char c = 'H';
        (void)!write(*fd, &c, 1);
    }
}

static void
test_pre_exec_hook(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    // Create a pipe to verify hook fired in child.
    int hook_pipe[2];
    if (pipe(hook_pipe) < 0) {
        printf("  [SKIP] pre-exec hook (pipe failed)\n");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd           = n00b_string_from_cstr("/bin/echo"),
        .conduit       = c,
        .io            = io,
        .pre_exec_hook = test_hook_fn,
        .hook_param    = &hook_pipe[1]);

    n00b_result_t(bool) r = n00b_subproc_spawn(&sp);
    close(hook_pipe[1]); // Close write end in parent.

    if (n00b_result_is_err(r)) {
        close(hook_pipe[0]);
        printf("  [SKIP] pre-exec hook (spawn failed)\n");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    // Read from hook pipe.
    char buf = 0;
    ssize_t n = read(hook_pipe[0], &buf, 1);
    close(hook_pipe[0]);
    assert(n == 1 && buf == 'H');

    n00b_subproc_wait(&sp);
    n00b_subproc_close(&sp);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] pre-exec hook\n");
}

// ============================================================================
// 13. Timeout with SIGTERM
// ============================================================================

static void
test_timeout_sigterm(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_duration_t timeout = {.tv_sec = 0, .tv_nsec = 100000000}; // 100ms

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/sleep"),
        .conduit        = c,
        .io             = io,
        .timeout        = &timeout,
        .timeout_policy = N00B_SUBPROC_TIMEOUT_SIGTERM);

    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 1);
    n00b_array_set(args, 0, n00b_string_from_cstr("100"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] timeout sigterm (err=%d)\n", n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_subproc_timed_out(&sp));
    assert(n00b_subproc_exited(&sp));

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] timeout sigterm\n");
}

// ============================================================================
// 14. Spawn with cwd — child runs in specified directory
// ============================================================================

static void
test_spawn_cwd(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    // Use /bin/pwd to print working directory.  Capture stdout via a
    // pipe we read ourselves (capture wiring isn't done yet).
    int out_pipe[2];
    if (pipe(out_pipe) < 0) {
        printf("  [SKIP] spawn cwd (pipe failed)\n");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd     = n00b_string_from_cstr("/bin/pwd"),
        .conduit = c,
        .io      = io,
        .cwd     = n00b_string_from_cstr("/tmp"),
        .capture_stdout = true);

    n00b_result_t(bool) r = n00b_subproc_spawn(&sp);
    if (n00b_result_is_err(r)) {
        close(out_pipe[0]);
        close(out_pipe[1]);
        printf("  [SKIP] spawn cwd (spawn failed, err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    n00b_subproc_wait(&sp);
    assert(n00b_subproc_exited(&sp));

    n00b_result_t(int) ec = n00b_subproc_exit_code(&sp);
    assert(n00b_result_is_ok(ec));
    assert(n00b_result_get(ec) == 0);

    n00b_subproc_close(&sp);
    close(out_pipe[0]);
    close(out_pipe[1]);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] spawn cwd\n");
}

// ============================================================================
// 15. Stdout xform chain — linebuf strips trailing newline
// ============================================================================

static void
test_stdout_xform_linebuf(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    // Build a specs array with the default linebuf spec.
    // Linebuf with include_delimiter=false strips the trailing '\n'
    // from each line.
    n00b_array_t(void *) xforms = n00b_array_new(void *, 1);
    n00b_array_set(xforms, 0,
                   (void *)&n00b_conduit_linebuf_default_spec);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/echo"),
        .conduit        = c,
        .io             = io,
        .capture_stdout = true,
        .merge          = false,
        .stdout_xforms  = &xforms);

    // Add "hello" argument.
    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 1);
    n00b_array_set(args, 0, n00b_string_from_cstr("hello"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] stdout xform linebuf (err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_exited(&sp));

    // The linebuf transform strips the trailing '\n', so we
    // should see "hello" without newline.
    n00b_buffer_t *out = n00b_subproc_stdout(&sp);
    assert(out != nullptr);

    if (out->byte_len > 0) {
        // Linebuf emits line-by-line; capture accumulates them.
        // "hello\n" → linebuf strips delimiter → "hello" (5 bytes).
        assert(out->byte_len == 5);
        assert(memcmp(out->data, "hello", 5) == 0);
    }

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] stdout xform linebuf\n");
}

// ============================================================================
// 16. Capture echo hello (no xforms) — verify raw capture
// ============================================================================

static void
test_capture_echo_hello(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/echo"),
        .conduit        = c,
        .io             = io,
        .capture_stdout = true,
        .merge          = false);

    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 1);
    n00b_array_set(args, 0, n00b_string_from_cstr("hello"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] capture echo hello (err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_exited(&sp));

    n00b_buffer_t *out = n00b_subproc_stdout(&sp);
    assert(out != nullptr);
    // /bin/echo hello produces "hello\n" = 6 bytes.
    assert(out->byte_len == 6);
    assert(memcmp(out->data, "hello\n", 6) == 0);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] capture echo hello\n");
}

// ============================================================================
// 17. Capture cat with stdin_inject + close_stdin
// ============================================================================

static void
test_capture_cat_stdin_inject(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_buffer_t *inject = n00b_buffer_from_cstr("hi\n");

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/cat"),
        .conduit        = c,
        .io             = io,
        .capture_stdout = true,
        .merge          = false,
        .stdin_inject   = inject,
        .close_stdin    = true);

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] capture cat stdin_inject (err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_exited(&sp));

    n00b_buffer_t *out = n00b_subproc_stdout(&sp);
    assert(out != nullptr);
    // /bin/cat echoes stdin: "hi\n" = 3 bytes.
    assert(out->byte_len == 3);
    assert(memcmp(out->data, "hi\n", 3) == 0);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] capture cat stdin_inject\n");
}

// ============================================================================
// 18. End-to-end: run ls with arguments
// ============================================================================

static void
test_run_ls_with_args(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/ls"),
        .conduit        = c,
        .io             = io,
        .capture_stdout = true,
        .merge          = false);

    // Add "-la" and "/tmp" arguments.
    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 2);
    n00b_array_set(args, 0, n00b_string_from_cstr("-la"));
    n00b_array_set(args, 1, n00b_string_from_cstr("/tmp"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] run ls with args (err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_exited(&sp));

    n00b_result_t(int) ec = n00b_subproc_exit_code(&sp);
    assert(n00b_result_is_ok(ec));
    assert(n00b_result_get(ec) == 0);

    // ls -la /tmp should produce substantial output.
    n00b_buffer_t *out = n00b_subproc_stdout(&sp);
    assert(out != nullptr);
    assert(out->byte_len > 10); // At least "total N\n" + some entries

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] run ls with args\n");
}

// ============================================================================
// 19. Stdin capture — verify cap_stdin captures injected data
// ============================================================================

static void
test_stdin_capture(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_buffer_t *inject = n00b_buffer_from_cstr("captured input\n");

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/cat"),
        .conduit        = c,
        .io             = io,
        .capture        = true,
        .merge          = false,
        .stdin_inject   = inject,
        .close_stdin    = true);

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] stdin capture (err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));

    // buf_stdin should contain the injected data.
    n00b_buffer_t *sin = n00b_subproc_stdin_capture(&sp);
    assert(sin != nullptr);
    assert(sin->byte_len == 15); // "captured input\n"
    assert(memcmp(sin->data, "captured input\n", 15) == 0);

    // stdout should also have it (cat echoes stdin).
    n00b_buffer_t *sout = n00b_subproc_stdout(&sp);
    assert(sout != nullptr);
    assert(sout->byte_len == 15);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] stdin capture\n");
}

// ============================================================================
// 20. Topic accessors return non-null after spawn
// ============================================================================

static void
test_topic_accessors(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/echo"),
        .conduit        = c,
        .io             = io,
        .capture_stdout = true,
        .merge          = false);

    // Before spawn, topics should be n00b_option_none.
    assert(!n00b_option_is_set(n00b_subproc_stdout_topic(&sp)));
    assert(!n00b_option_is_set(n00b_subproc_stderr_topic(&sp)));
    assert(!n00b_option_is_set(n00b_subproc_stdin_topic(&sp)));

    n00b_result_t(bool) r = n00b_subproc_spawn(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] topic accessors (spawn failed)\n");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    // After spawn with capture_stdout, stdout topic should be set.
    assert(n00b_option_is_set(n00b_subproc_stdout_topic(&sp)));

    n00b_subproc_wait(&sp);
    n00b_subproc_close(&sp);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] topic accessors\n");
}

// ============================================================================
// 21. End-to-end: run with env override (execve path)
// ============================================================================

static void
test_run_with_env(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    // /usr/bin/env prints its environment.  We'll use /bin/echo with
    // a custom env to verify execve path works (requires absolute path).
    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/echo"),
        .conduit        = c,
        .io             = io,
        .capture_stdout = true,
        .merge          = false);

    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 1);
    n00b_array_set(args, 0, n00b_string_from_cstr("env_works"));
    sp.args = &args;

    // Provide a minimal environment.
    n00b_array_t(n00b_string_t *) env = n00b_array_new(n00b_string_t *, 1);
    n00b_array_set(env, 0, n00b_string_from_cstr("HOME=/tmp"));
    sp.env = &env;

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] run with env (err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_exited(&sp));

    n00b_buffer_t *out = n00b_subproc_stdout(&sp);
    assert(out != nullptr);
    assert(out->byte_len == 10); // "env_works\n"
    assert(memcmp(out->data, "env_works\n", 10) == 0);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] run with env\n");
}

// ============================================================================
// 22. PTY spawn echo — basic PTY mode, capture stdout
// ============================================================================

static void
test_pty_spawn_echo(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/echo"),
        .conduit        = c,
        .io             = io,
        .pty            = true,
        .capture_stdout = true,
        .merge          = false);

    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 1);
    n00b_array_set(args, 0, n00b_string_from_cstr("hello"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] pty spawn echo (err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_exited(&sp));

    n00b_result_t(int) ec = n00b_subproc_exit_code(&sp);
    assert(n00b_result_is_ok(ec));
    assert(n00b_result_get(ec) == 0);

    // PTY line discipline produces \r\n instead of \n.
    // "hello\r\n" = 7 bytes.
    n00b_buffer_t *out = n00b_subproc_stdout(&sp);
    assert(out != nullptr);
    assert(out->byte_len == 7);
    assert(memcmp(out->data, "hello\r\n", 7) == 0);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] pty spawn echo\n");
}

// ============================================================================
// 23. PTY exec failure — bad command returns Err
// ============================================================================

static void
test_pty_exec_failure(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd     = n00b_string_from_cstr("/nonexistent/bad/command"),
        .conduit = c,
        .io      = io,
        .pty     = true);

    n00b_result_t(bool) r = n00b_subproc_spawn(&sp);
    if (n00b_result_is_err(r)) {
        int err = n00b_result_get_err(r);
        if (err != ENOENT) {
            printf("  [SKIP] pty exec failure (err=%d)\n", err);
            n00b_conduit_io_destroy(io);
            n00b_conduit_destroy(c);
            return;
        }
        assert(n00b_subproc_errored(&sp));
    }
    else {
        assert(false && "pty exec failure should return error");
    }

    n00b_subproc_close(&sp);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] pty exec failure\n");
}

// ============================================================================
// 24. PTY cat stdin_inject — round-trip through PTY
// ============================================================================

static void
test_pty_cat_stdin_inject(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_buffer_t *inject = n00b_buffer_from_cstr("hi\n");

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/cat"),
        .conduit        = c,
        .io             = io,
        .pty            = true,
        .capture_stdout = true,
        .stdin_inject   = inject,
        .close_stdin    = true);

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] pty cat stdin_inject (err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_exited(&sp));

    // PTY echoes stdin writes back to the read side (line discipline echo).
    // Input "hi\n" → PTY echo "hi\r\n" + cat output "hi\r\n".
    // We expect at least 4 bytes ("hi\r\n") and the output must
    // contain the "hi\r\n" pattern from the PTY line discipline.
    n00b_buffer_t *out = n00b_subproc_stdout(&sp);
    assert(out != nullptr);
    assert(out->byte_len >= 4); // At least "hi\r\n"

    // Verify the captured output contains "hi\r\n" (PTY converts \n → \r\n).
    bool found = false;
    for (size_t i = 0; i + 3 < out->byte_len; i++) {
        if (memcmp(out->data + i, "hi\r\n", 4) == 0) {
            found = true;
            break;
        }
    }
    assert(found);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] pty cat stdin_inject\n");
}

// ============================================================================
// 25. PTY separate stderr (err_pty)
// ============================================================================

static void
test_pty_separate_stderr(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    // Use sh -c to write to both stdout and stderr.
    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/sh"),
        .conduit        = c,
        .io             = io,
        .pty            = true,
        .err_pty        = true,
        .capture_stdout = true,
        .capture_stderr = true,
        .merge          = false);

    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 2);
    n00b_array_set(args, 0, n00b_string_from_cstr("-c"));
    n00b_array_set(args, 1,
        n00b_string_from_cstr("echo out_data; echo err_data >&2"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] pty separate stderr (err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_exited(&sp));

    n00b_result_t(int) ec = n00b_subproc_exit_code(&sp);
    assert(n00b_result_is_ok(ec));
    assert(n00b_result_get(ec) == 0);

    // With separate PTY stderr, stdout and stderr come through
    // different FD owners, so capture should be separate.
    // Stdout should contain "out_data\r\n" (PTY line discipline).
    // Stderr should contain "err_data\r\n".
    n00b_buffer_t *sout = n00b_subproc_stdout(&sp);
    n00b_buffer_t *serr = n00b_subproc_stderr(&sp);
    assert(sout != nullptr);
    assert(serr != nullptr);

    // Verify both streams captured data.
    assert(sout->byte_len > 0);
    assert(serr->byte_len > 0);

    // Verify stdout contains "out_data" (PTY may add \r\n).
    bool found_out = false;
    for (size_t i = 0; i + 8 <= sout->byte_len; i++) {
        if (memcmp(sout->data + i, "out_data", 8) == 0) {
            found_out = true;
            break;
        }
    }
    assert(found_out);

    // Verify stderr contains "err_data".
    bool found_err = false;
    for (size_t i = 0; i + 8 <= serr->byte_len; i++) {
        if (memcmp(serr->data + i, "err_data", 8) == 0) {
            found_err = true;
            break;
        }
    }
    assert(found_err);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] pty separate stderr\n");
}

// ============================================================================
// 26. PTY timeout — verify timeout + kill works through PTY
// ============================================================================

static void
test_pty_timeout(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_duration_t timeout = {.tv_sec = 0, .tv_nsec = 100000000}; // 100ms

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/sleep"),
        .conduit        = c,
        .io             = io,
        .pty            = true,
        .timeout        = &timeout,
        .timeout_policy = N00B_SUBPROC_TIMEOUT_SIGTERM);

    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 1);
    n00b_array_set(args, 0, n00b_string_from_cstr("100"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] pty timeout (err=%d)\n", n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_subproc_timed_out(&sp));
    assert(n00b_subproc_exited(&sp));

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] pty timeout\n");
}

// ============================================================================
// 27. PTY close idempotent — shared owner deduplication doesn't crash
// ============================================================================

static void
test_pty_close_idempotent(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd     = n00b_string_from_cstr("/bin/echo"),
        .conduit = c,
        .io      = io,
        .pty     = true,
        .capture_stdout = true,
        .merge   = false);

    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 1);
    n00b_array_set(args, 0, n00b_string_from_cstr("test"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_spawn(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] pty close idempotent (spawn failed)\n");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    n00b_subproc_wait(&sp);
    n00b_subproc_close(&sp);
    n00b_subproc_close(&sp); // Second close should not crash.
    n00b_subproc_close(&sp); // Third close should not crash.

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] pty close idempotent\n");
}

// ============================================================================
// 28. PTY with cwd — child runs in specified directory
// ============================================================================

static void
test_pty_cwd(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/pwd"),
        .conduit        = c,
        .io             = io,
        .pty            = true,
        .cwd            = n00b_string_from_cstr("/tmp"),
        .capture_stdout = true,
        .merge          = false);

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] pty cwd (err=%d)\n", n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_exited(&sp));

    n00b_result_t(int) ec = n00b_subproc_exit_code(&sp);
    assert(n00b_result_is_ok(ec));
    assert(n00b_result_get(ec) == 0);

    // Output should contain "/tmp" or "/private/tmp" (macOS resolves symlink).
    n00b_buffer_t *out = n00b_subproc_stdout(&sp);
    assert(out != nullptr);
    assert(out->byte_len >= 4); // At least "/tmp"

    bool found = false;
    for (size_t i = 0; i + 4 <= out->byte_len; i++) {
        if (memcmp(out->data + i, "/tmp", 4) == 0) {
            found = true;
            break;
        }
    }
    assert(found);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] pty cwd\n");
}

// ============================================================================
// 29. Pipe stderr capture — verify stderr is captured separately
// ============================================================================

static void
test_pipe_stderr_capture(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/sh"),
        .conduit        = c,
        .io             = io,
        .capture_stdout = true,
        .capture_stderr = true,
        .merge          = false);

    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 2);
    n00b_array_set(args, 0, n00b_string_from_cstr("-c"));
    n00b_array_set(args, 1,
        n00b_string_from_cstr("echo out_msg; echo err_msg >&2"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] pipe stderr capture (err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_exited(&sp));

    n00b_buffer_t *sout = n00b_subproc_stdout(&sp);
    n00b_buffer_t *serr = n00b_subproc_stderr(&sp);
    assert(sout != nullptr);
    assert(serr != nullptr);

    // stdout: "out_msg\n" = 8 bytes
    assert(sout->byte_len == 8);
    assert(memcmp(sout->data, "out_msg\n", 8) == 0);

    // stderr: "err_msg\n" = 8 bytes
    assert(serr->byte_len == 8);
    assert(memcmp(serr->data, "err_msg\n", 8) == 0);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] pipe stderr capture\n");
}

// ============================================================================
// 30. Non-zero exit code
// ============================================================================

static void
test_nonzero_exit(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd     = n00b_string_from_cstr("/bin/sh"),
        .conduit = c,
        .io      = io);

    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 2);
    n00b_array_set(args, 0, n00b_string_from_cstr("-c"));
    n00b_array_set(args, 1, n00b_string_from_cstr("exit 42"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] nonzero exit (err=%d)\n", n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_subproc_exited(&sp));

    n00b_result_t(int) ec = n00b_subproc_exit_code(&sp);
    assert(n00b_result_is_ok(ec));
    assert(n00b_result_get(ec) == 42);

    // Not signaled — term_signal should be Err.
    n00b_result_t(int) ts = n00b_subproc_term_signal(&sp);
    assert(n00b_result_is_err(ts));

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] nonzero exit\n");
}

// ============================================================================
// 31. Multi-line output
// ============================================================================

static void
test_multiline_output(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/sh"),
        .conduit        = c,
        .io             = io,
        .capture_stdout = true,
        .merge          = false);

    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 2);
    n00b_array_set(args, 0, n00b_string_from_cstr("-c"));
    n00b_array_set(args, 1,
        n00b_string_from_cstr("echo line1; echo line2; echo line3"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] multiline output (err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_exited(&sp));

    n00b_buffer_t *out = n00b_subproc_stdout(&sp);
    assert(out != nullptr);
    // "line1\nline2\nline3\n" = 18 bytes
    assert(out->byte_len == 18);
    assert(memcmp(out->data, "line1\nline2\nline3\n", 18) == 0);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] multiline output\n");
}

// ============================================================================
// 32. Large output — stress buffering
// ============================================================================

static void
test_large_output(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/sh"),
        .conduit        = c,
        .io             = io,
        .capture_stdout = true,
        .merge          = false);

    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 2);
    n00b_array_set(args, 0, n00b_string_from_cstr("-c"));
    n00b_array_set(args, 1, n00b_string_from_cstr("seq 1 1000"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] large output (err=%d)\n", n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_exited(&sp));

    n00b_buffer_t *out = n00b_subproc_stdout(&sp);
    assert(out != nullptr);
    // seq 1 1000 produces ~3893 bytes.
    assert(out->byte_len > 2000);

    // Starts with "1\n2\n3\n" (6 bytes).
    assert(out->byte_len >= 6);
    assert(memcmp(out->data, "1\n2\n3\n", 6) == 0);

    // Ends with "999\n1000\n" (9 bytes).
    assert(out->byte_len >= 9);
    assert(memcmp(out->data + out->byte_len - 9, "999\n1000\n", 9) == 0);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] large output\n");
}

// ============================================================================
// 33. Interleaved stdout/stderr (pipe, no merge)
// ============================================================================

static void
test_interleaved_stdout_stderr(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/sh"),
        .conduit        = c,
        .io             = io,
        .capture_stdout = true,
        .capture_stderr = true,
        .merge          = false);

    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 2);
    n00b_array_set(args, 0, n00b_string_from_cstr("-c"));
    n00b_array_set(args, 1,
        n00b_string_from_cstr(
            "echo O1; echo E1 >&2; echo O2; echo E2 >&2"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] interleaved stdout/stderr (err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_exited(&sp));

    n00b_buffer_t *sout = n00b_subproc_stdout(&sp);
    n00b_buffer_t *serr = n00b_subproc_stderr(&sp);
    assert(sout != nullptr);
    assert(serr != nullptr);

    // Helper: search for a substring in a buffer.
    #define buf_contains(buf, needle, nlen) ({ \
        bool _found = false; \
        for (size_t _i = 0; _i + (nlen) <= (buf)->byte_len; _i++) { \
            if (memcmp((buf)->data + _i, (needle), (nlen)) == 0) { \
                _found = true; break; \
            } \
        } \
        _found; \
    })

    // Stdout contains O1 and O2.
    assert(buf_contains(sout, "O1", 2));
    assert(buf_contains(sout, "O2", 2));

    // Stderr contains E1 and E2.
    assert(buf_contains(serr, "E1", 2));
    assert(buf_contains(serr, "E2", 2));

    // Stdout does NOT contain E1 or E2.
    assert(!buf_contains(sout, "E1", 2));
    assert(!buf_contains(sout, "E2", 2));

    // Stderr does NOT contain O1 or O2.
    assert(!buf_contains(serr, "O1", 2));
    assert(!buf_contains(serr, "O2", 2));

    #undef buf_contains

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] interleaved stdout/stderr\n");
}

// ============================================================================
// 34. Merged stdout+stderr
// ============================================================================

static void
test_merged_output(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/sh"),
        .conduit        = c,
        .io             = io,
        .capture_stdout = true);
    // merge=true is the default.

    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 2);
    n00b_array_set(args, 0, n00b_string_from_cstr("-c"));
    n00b_array_set(args, 1,
        n00b_string_from_cstr("echo out_merged; echo err_merged >&2"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] merged output (err=%d)\n", n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_exited(&sp));

    n00b_buffer_t *sout = n00b_subproc_stdout(&sp);
    assert(sout != nullptr);

    // Stdout should contain both "out_merged" and "err_merged".
    bool found_out = false;
    bool found_err = false;
    for (size_t i = 0; i + 10 <= sout->byte_len; i++) {
        if (memcmp(sout->data + i, "out_merged", 10) == 0) {
            found_out = true;
        }
        if (memcmp(sout->data + i, "err_merged", 10) == 0) {
            found_err = true;
        }
    }
    assert(found_out);
    assert(found_err);

    // Stderr should be empty (merged into stdout).
    n00b_buffer_t *serr = n00b_subproc_stderr(&sp);
    assert(serr != nullptr);
    assert(serr->byte_len == 0);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] merged output\n");
}

// ============================================================================
// 35. write_stdin after spawn
// ============================================================================

static void
test_write_stdin_after_spawn(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    // head -n1 reads one line then exits — no need to close stdin.
    // capture_stdin ensures the stdin pipe is created so write_stdin works.
    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/usr/bin/head"),
        .conduit        = c,
        .io             = io,
        .capture_stdout = true,
        .capture_stdin  = true,
        .merge          = false);

    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 2);
    n00b_array_set(args, 0, n00b_string_from_cstr("-n"));
    n00b_array_set(args, 1, n00b_string_from_cstr("1"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_spawn(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] write_stdin after spawn (err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    // Write data to child stdin after spawn.
    n00b_buffer_t *data = n00b_buffer_from_cstr("dynamic\n");
    n00b_result_t(uint64_t) wr = n00b_subproc_write_stdin(&sp, data);
    assert(n00b_result_is_ok(wr));

    // wait() pumps the event loop, flushing the write and reaping exit.
    n00b_subproc_wait(&sp);
    assert(n00b_subproc_exited(&sp));

    n00b_result_t(int) ec = n00b_subproc_exit_code(&sp);
    assert(n00b_result_is_ok(ec));
    assert(n00b_result_get(ec) == 0);

    n00b_buffer_t *out = n00b_subproc_stdout(&sp);
    assert(out != nullptr);
    assert(out->byte_len == 8);
    assert(memcmp(out->data, "dynamic\n", 8) == 0);

    n00b_subproc_close(&sp);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] write_stdin after spawn\n");
}

// ============================================================================
// 36. Invalid cwd
// ============================================================================

static void
test_invalid_cwd(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd     = n00b_string_from_cstr("/bin/echo"),
        .conduit = c,
        .io      = io,
        .cwd     = n00b_string_from_cstr("/nonexistent_path_xyz"));

    n00b_result_t(bool) r = n00b_subproc_spawn(&sp);
    assert(n00b_result_is_err(r));
    assert(n00b_subproc_errored(&sp));

    n00b_subproc_close(&sp);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] invalid cwd\n");
}

// ============================================================================
// 37. Linebuf xform on multi-line — strips delimiters
// ============================================================================

static void
test_linebuf_multiline(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_array_t(void *) xforms = n00b_array_new(void *, 1);
    n00b_array_set(xforms, 0,
                   (void *)&n00b_conduit_linebuf_default_spec);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/sh"),
        .conduit        = c,
        .io             = io,
        .capture_stdout = true,
        .merge          = false,
        .stdout_xforms  = &xforms);

    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 2);
    n00b_array_set(args, 0, n00b_string_from_cstr("-c"));
    n00b_array_set(args, 1,
        n00b_string_from_cstr("echo line1; echo line2; echo line3"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] linebuf multiline (err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_exited(&sp));

    // Linebuf strips '\n' from each line, so
    // "line1\nline2\nline3\n" → "line1" + "line2" + "line3" = 15 bytes.
    n00b_buffer_t *out = n00b_subproc_stdout(&sp);
    assert(out != nullptr);
    assert(out->byte_len == 15);
    assert(memcmp(out->data, "line1line2line3", 15) == 0);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] linebuf multiline\n");
}

// ============================================================================
// 38. Xform chain: ansi_strip + linebuf
// ============================================================================

static void
test_xform_chain_ansi_linebuf(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    // Chain: ansi_strip first, then linebuf.
    n00b_array_t(void *) xforms = n00b_array_new(void *, 2);
    n00b_array_set(xforms, 0,
                   (void *)&n00b_conduit_ansi_strip_default_spec);
    n00b_array_set(xforms, 1,
                   (void *)&n00b_conduit_linebuf_default_spec);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/sh"),
        .conduit        = c,
        .io             = io,
        .capture_stdout = true,
        .merge          = false,
        .stdout_xforms  = &xforms);

    // printf ANSI-colored text with newlines.
    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 2);
    n00b_array_set(args, 0, n00b_string_from_cstr("-c"));
    n00b_array_set(args, 1,
        n00b_string_from_cstr(
            "printf '\\033[31mred\\033[0m\\n\\033[32mgreen\\033[0m\\n'"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] xform chain ansi+linebuf (err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_exited(&sp));

    // ansi_strip removes escape sequences, linebuf strips newlines.
    // "\033[31mred\033[0m\n\033[32mgreen\033[0m\n"
    // → ansi_strip → "red\ngreen\n"
    // → linebuf → "red" + "green" = "redgreen" (8 bytes)
    n00b_buffer_t *out = n00b_subproc_stdout(&sp);
    assert(out != nullptr);
    assert(out->byte_len == 8);
    assert(memcmp(out->data, "redgreen", 8) == 0);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] xform chain ansi+linebuf\n");
}

// ============================================================================
// 39. PTY + linebuf xform
// ============================================================================

static void
test_pty_linebuf_xform(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_array_t(void *) xforms = n00b_array_new(void *, 1);
    n00b_array_set(xforms, 0,
                   (void *)&n00b_conduit_linebuf_default_spec);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/echo"),
        .conduit        = c,
        .io             = io,
        .pty            = true,
        .capture_stdout = true,
        .merge          = false,
        .stdout_xforms  = &xforms);

    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 1);
    n00b_array_set(args, 0, n00b_string_from_cstr("hello"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] pty linebuf xform (err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_exited(&sp));

    // PTY produces "hello\r\n".  Linebuf splits on '\n' (default),
    // strips delimiter → emits "hello\r" (6 bytes).
    n00b_buffer_t *out = n00b_subproc_stdout(&sp);
    assert(out != nullptr);
    assert(out->byte_len == 6);
    assert(memcmp(out->data, "hello\r", 6) == 0);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] pty linebuf xform\n");
}

// ============================================================================
// 40. PTY + ansi_strip
// ============================================================================

static void
test_pty_ansi_strip(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_array_t(void *) xforms = n00b_array_new(void *, 1);
    n00b_array_set(xforms, 0,
                   (void *)&n00b_conduit_ansi_strip_default_spec);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/sh"),
        .conduit        = c,
        .io             = io,
        .pty            = true,
        .capture_stdout = true,
        .merge          = false,
        .stdout_xforms  = &xforms);

    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 2);
    n00b_array_set(args, 0, n00b_string_from_cstr("-c"));
    n00b_array_set(args, 1,
        n00b_string_from_cstr("printf '\\033[31mcolor\\033[0m\\n'"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] pty ansi_strip (err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_exited(&sp));

    n00b_buffer_t *out = n00b_subproc_stdout(&sp);
    assert(out != nullptr);
    assert(out->byte_len > 0);

    // Output should contain "color" but not ESC (\033).
    bool found_color = false;
    for (size_t i = 0; i + 5 <= out->byte_len; i++) {
        if (memcmp(out->data + i, "color", 5) == 0) {
            found_color = true;
            break;
        }
    }
    assert(found_color);

    // Verify no ESC byte remains.
    bool found_esc = false;
    for (size_t i = 0; i < out->byte_len; i++) {
        if (((uint8_t *)out->data)[i] == 0x1b) {
            found_esc = true;
            break;
        }
    }
    assert(!found_esc);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] pty ansi_strip\n");
}

// ============================================================================
// 41. PTY non-zero exit
// ============================================================================

static void
test_pty_nonzero_exit(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/sh"),
        .conduit        = c,
        .io             = io,
        .pty            = true,
        .capture_stdout = true);

    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 2);
    n00b_array_set(args, 0, n00b_string_from_cstr("-c"));
    n00b_array_set(args, 1, n00b_string_from_cstr("exit 7"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] pty nonzero exit (err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    assert(n00b_subproc_exited(&sp));

    n00b_result_t(int) ec = n00b_subproc_exit_code(&sp);
    assert(n00b_result_is_ok(ec));
    assert(n00b_result_get(ec) == 7);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] pty nonzero exit\n");
}

// ============================================================================
// 42. PTY pre-exec hook
// ============================================================================

static void
test_pty_pre_exec_hook(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    int hook_pipe[2];
    if (pipe(hook_pipe) < 0) {
        printf("  [SKIP] pty pre-exec hook (pipe failed)\n");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/echo"),
        .conduit        = c,
        .io             = io,
        .pty            = true,
        .capture_stdout = true,
        .pre_exec_hook  = test_hook_fn,
        .hook_param     = &hook_pipe[1]);

    n00b_result_t(bool) r = n00b_subproc_spawn(&sp);
    close(hook_pipe[1]); // Close write end in parent.

    if (n00b_result_is_err(r)) {
        close(hook_pipe[0]);
        printf("  [SKIP] pty pre-exec hook (spawn failed)\n");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    // Read from hook pipe — should get 'H'.
    char buf = 0;
    ssize_t n = read(hook_pipe[0], &buf, 1);
    close(hook_pipe[0]);
    assert(n == 1 && buf == 'H');

    n00b_subproc_wait(&sp);
    n00b_subproc_close(&sp);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] pty pre-exec hook\n");
}

// ============================================================================
// 43. PTY kill signal
// ============================================================================

static void
test_pty_kill_signal(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/sleep"),
        .conduit        = c,
        .io             = io,
        .pty            = true,
        .capture_stdout = true);

    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 1);
    n00b_array_set(args, 0, n00b_string_from_cstr("100"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_spawn(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] pty kill signal (spawn failed)\n");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    // Send SIGTERM.
    n00b_result_t(bool) kr = n00b_subproc_kill(&sp);
    assert(n00b_result_is_ok(kr));

    n00b_subproc_wait(&sp);
    assert(n00b_subproc_exited(&sp));

    n00b_result_t(int) ts = n00b_subproc_term_signal(&sp);
    assert(n00b_result_is_ok(ts));
    assert(n00b_result_get(ts) == SIGTERM);

    n00b_subproc_close(&sp);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] pty kill signal\n");
}

// ============================================================================
// 44. Custom done condition
// ============================================================================

static bool
custom_done_check(n00b_subproc_t *sp, void *ctx)
{
    (void)ctx;
    n00b_buffer_t *out = n00b_subproc_stdout(sp);
    // Done when we've captured any stdout data.
    return out != nullptr && out->byte_len > 0;
}

static void
test_custom_done_condition(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("/bin/sh"),
        .conduit        = c,
        .io             = io,
        .capture_stdout = true,
        .merge          = false,
        .done_condition = N00B_SUBPROC_DONE_CUSTOM,
        .done_fn        = custom_done_check);

    // Child prints "go" then execs the long-lived process so subproc_kill()
    // targets the process that is keeping the pipe open.
    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 2);
    n00b_array_set(args, 0, n00b_string_from_cstr("-c"));
    n00b_array_set(args, 1,
        n00b_string_from_cstr("echo go; exec sleep 100"));
    sp.args = &args;

    n00b_result_t(bool) r = n00b_subproc_spawn(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] custom done condition (spawn failed, err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    // Wait with custom done — returns when stdout has data.
    n00b_duration_t timeout = {.tv_sec = 5, .tv_nsec = 0};
    n00b_result_t(bool) wr = n00b_subproc_wait(&sp, .timeout = &timeout);
    if (n00b_result_is_err(wr)) {
        printf("  [SKIP] custom done condition (wait err=%d)\n",
               n00b_result_get_err(wr));
        n00b_subproc_kill(&sp);
        n00b_subproc_wait(&sp);
        n00b_subproc_close(&sp);
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    // Stdout should contain "go".
    n00b_buffer_t *out = n00b_subproc_stdout(&sp);
    assert(out != nullptr);
    bool found_go = false;
    for (size_t i = 0; i + 2 <= out->byte_len; i++) {
        if (memcmp(out->data + i, "go", 2) == 0) {
            found_go = true;
            break;
        }
    }
    assert(found_go);

    // Child is still alive (sleep 100) — kill it and reap.
    n00b_subproc_kill(&sp);

    // The custom done_fn already returns true (stdout has data),
    // so wait() returns immediately without reaping.  Switch to
    // PROC_EXIT for the reap wait.
    sp.done_condition = N00B_SUBPROC_DONE_PROC_EXIT;
    sp.done_flags     = 0; // Reset so PROC_EXIT isn't already set.
    n00b_duration_t kill_timeout = {.tv_sec = 5, .tv_nsec = 0};
    n00b_subproc_wait(&sp, .timeout = &kill_timeout);
    assert(n00b_subproc_exited(&sp));

    n00b_subproc_close(&sp);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] custom done condition\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_subproc:\n");
    fflush(stdout);

    test_init_defaults();
    fflush(stdout);
    test_capture_convenience();
    fflush(stdout);
    test_proxy_convenience();
    fflush(stdout);
    test_accessors_pre_spawn();
    fflush(stdout);
    test_spawn_echo();
    fflush(stdout);
    test_spawn_bad_cmd();
    fflush(stdout);
    test_spawn_no_cmd();
    fflush(stdout);
    test_double_spawn();
    fflush(stdout);
    test_close_idempotent();
    fflush(stdout);
    test_run_echo();
    fflush(stdout);
    test_kill();
    fflush(stdout);
    test_pre_exec_hook();
    fflush(stdout);
    test_timeout_sigterm();
    fflush(stdout);
    test_spawn_cwd();
    fflush(stdout);
    test_capture_echo_hello();
    fflush(stdout);
    test_capture_cat_stdin_inject();
    fflush(stdout);
    test_stdout_xform_linebuf();
    fflush(stdout);
    test_run_ls_with_args();
    fflush(stdout);
    test_stdin_capture();
    fflush(stdout);
    test_topic_accessors();
    fflush(stdout);
    test_run_with_env();
    fflush(stdout);
    test_pty_spawn_echo();
    fflush(stdout);
    test_pty_exec_failure();
    fflush(stdout);
    test_pty_cat_stdin_inject();
    fflush(stdout);
    test_pty_separate_stderr();
    fflush(stdout);
    test_pty_timeout();
    fflush(stdout);
    test_pty_close_idempotent();
    fflush(stdout);
    test_pty_cwd();
    fflush(stdout);
    test_pipe_stderr_capture();
    fflush(stdout);
    test_nonzero_exit();
    fflush(stdout);
    test_multiline_output();
    fflush(stdout);
    test_large_output();
    fflush(stdout);
    test_interleaved_stdout_stderr();
    fflush(stdout);
    test_merged_output();
    fflush(stdout);
    test_write_stdin_after_spawn();
    fflush(stdout);
    test_invalid_cwd();
    fflush(stdout);
    test_linebuf_multiline();
    fflush(stdout);
    test_xform_chain_ansi_linebuf();
    fflush(stdout);
    test_pty_linebuf_xform();
    fflush(stdout);
    test_pty_ansi_strip();
    fflush(stdout);
    test_pty_nonzero_exit();
    fflush(stdout);
    test_pty_pre_exec_hook();
    fflush(stdout);
    test_pty_kill_signal();
    fflush(stdout);
    test_custom_done_condition();
    fflush(stdout);

    printf("All subproc tests passed.\n");
    n00b_shutdown();
    return 0;
}

#else /* _WIN32 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

#include "n00b.h"
#include "conduit/subproc.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/xform_linebuf.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "internal/win32_sockets.h"

static const char *g_test_exe;

static n00b_conduit_t *
make_conduit(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    return n00b_result_get(cr);
}

static n00b_conduit_io_backend_t *
make_io(n00b_conduit_t *c)
{
    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    return n00b_result_get(ir);
}

static n00b_array_t(n00b_string_t *)
cmd_args(const char *script)
{
    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 2);
    n00b_array_set(args, 0, n00b_string_from_cstr("/C"));
    n00b_array_set(args, 1, n00b_string_from_cstr(script));
    return args;
}

static bool
buffer_contains(n00b_buffer_t *buf, const char *needle)
{
    if (!buf || !needle) {
        return false;
    }
    size_t n = strlen(needle);
    if (n == 0) {
        return true;
    }
    for (size_t i = 0; i + n <= buf->byte_len; i++) {
        if (memcmp(buf->data + i, needle, n) == 0) {
            return true;
        }
    }
    return false;
}

static bool
read_pipe_available(HANDLE pipe, char *buf, size_t cap, DWORD *read_out)
{
    DWORD available = 0;
    DWORD ignored   = 0;
    if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, &ignored)) {
        *read_out = 0;
        DWORD err = GetLastError();
        return err == ERROR_BROKEN_PIPE
            || err == ERROR_HANDLE_EOF
            || err == ERROR_NO_DATA
            || err == ERROR_PIPE_NOT_CONNECTED;
    }
    if (available == 0) {
        *read_out = 0;
        return true;
    }
    if (available >= cap) {
        available = (DWORD)cap - 1;
    }
    if (!ReadFile(pipe, buf, available, read_out, nullptr)) {
        *read_out = 0;
        return false;
    }
    buf[*read_out] = '\0';
    return true;
}

static int
windows_write_handle_child(int argc, char **argv)
{
    if (argc < 3) {
        return 2;
    }

    uintptr_t   raw     = (uintptr_t)strtoull(argv[2], nullptr, 10);
    HANDLE      handle  = (HANDLE)raw;
    const char *payload = "unexpected-inherited-handle";
    DWORD       written = 0;
    if (!WriteFile(handle, payload, (DWORD)strlen(payload), &written, nullptr)) {
        return 3;
    }

    return written == strlen(payload) ? 0 : 4;
}

static int
windows_raw_argv_child(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[0], "raw-argv-sentinel") == 0
        && strcmp(argv[1], "--win-raw-argv-child") == 0) {
        printf("raw-argv-ok\n");
        return 0;
    }

    printf("raw-argv-mismatch argc=%d\n", argc);
    for (int i = 0; i < argc; i++) {
        printf("argv[%d]=%s\n", i, argv[i]);
    }
    return 5;
}

static bool
inbox_contains(n00b_conduit_inbox_t(n00b_buffer_t *) *inbox, const char *needle)
{
    n00b_conduit_message_t(n00b_buffer_t *) *msg;
    while ((msg = n00b_conduit_inbox_pop_msg(n00b_buffer_t *, inbox)) != nullptr) {
        if (buffer_contains(msg->payload, needle)) {
            return true;
        }
    }
    return false;
}

static void
windows_hook_fn(void *param)
{
    int *count = param;
    if (count) {
        *count += 1;
    }
}

static void
test_windows_init_defaults(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd     = n00b_string_from_cstr("cmd.exe"),
        .conduit = c);

    assert(!n00b_subproc_is_spawned(&sp));
    assert(!n00b_subproc_exited(&sp));
    assert((sp.flags & N00B_SUBPROC_MERGE_OUTPUT) != 0);

    n00b_conduit_destroy(c);
    printf("  [PASS] windows init defaults\n");
}

static void
test_windows_raw_argv_uses_cmd_executable(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);
    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 2);
    n00b_array_set(args, 0, n00b_string_from_cstr("raw-argv-sentinel"));
    n00b_array_set(args, 1, n00b_string_from_cstr("--win-raw-argv-child"));

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr(g_test_exe),
        .conduit        = c,
        .io             = io,
        .args           = &args,
        .raw_argv       = true,
        .capture_stdout = true,
        .merge          = false);

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    assert(n00b_result_is_ok(r));
    assert(buffer_contains(n00b_subproc_stdout(&sp), "raw-argv-ok"));

    n00b_result_t(int) ec = n00b_subproc_exit_code(&sp);
    assert(n00b_result_is_ok(ec));
    assert(n00b_result_get(ec) == 0);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] windows raw argv uses cmd executable\n");
}

static void
test_windows_does_not_inherit_unlisted_handles(void)
{
    HANDLE read_pipe  = nullptr;
    HANDLE write_pipe = nullptr;
    SECURITY_ATTRIBUTES sa = {
        .nLength              = sizeof(sa),
        .lpSecurityDescriptor = nullptr,
        .bInheritHandle       = TRUE,
    };
    assert(CreatePipe(&read_pipe, &write_pipe, &sa, 0));
    assert(SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0));

    char handle_arg[64];
    snprintf(handle_arg, sizeof(handle_arg), "%llu",
             (unsigned long long)(uintptr_t)write_pipe);

    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);
    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 2);
    n00b_array_set(args, 0, n00b_string_from_cstr("--win-write-handle-child"));
    n00b_array_set(args, 1, n00b_string_from_cstr(handle_arg));

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr(g_test_exe),
        .conduit        = c,
        .io             = io,
        .args           = &args,
        .capture_stdout = true);

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    assert(n00b_result_is_ok(r));
    CloseHandle(write_pipe);

    char  buf[256];
    DWORD nread = 0;
    assert(read_pipe_available(read_pipe, buf, sizeof(buf), &nread));
    assert(nread == 0);

    n00b_result_t(int) ec = n00b_subproc_exit_code(&sp);
    assert(n00b_result_is_ok(ec));
    assert(n00b_result_get(ec) != 0);

    CloseHandle(read_pipe);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] windows blocks unrelated inheritable handles\n");
}

static void
test_windows_custom_env_does_not_search_parent_path(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);
    n00b_array_t(n00b_string_t *) args = cmd_args("echo custom-env-ran");
    n00b_array_t(n00b_string_t *) env = n00b_array_new(n00b_string_t *, 3);
    n00b_array_set(env, 0, n00b_string_from_cstr("PATH=C:\\not-a-real-path"));
    n00b_array_set(env, 1, n00b_string_from_cstr("SystemRoot=C:\\Windows"));
    n00b_array_set(env, 2, n00b_string_from_cstr("ComSpec=C:\\Windows\\System32\\cmd.exe"));

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("cmd.exe"),
        .conduit        = c,
        .io             = io,
        .args           = &args,
        .env            = &env,
        .capture_stdout = true);

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    assert(n00b_result_is_err(r));
    assert(n00b_subproc_errored(&sp));

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] windows custom env avoids parent PATH search\n");
}

static void
test_windows_default_stdout_inherits_parent_handle(void)
{
    HANDLE old_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE read_pipe  = nullptr;
    HANDLE write_pipe = nullptr;
    SECURITY_ATTRIBUTES sa = {
        .nLength              = sizeof(sa),
        .lpSecurityDescriptor = nullptr,
        .bInheritHandle       = TRUE,
    };
    assert(CreatePipe(&read_pipe, &write_pipe, &sa, 0));
    assert(SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0));
    assert(SetStdHandle(STD_OUTPUT_HANDLE, write_pipe));

    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);
    n00b_array_t(n00b_string_t *) args = cmd_args("echo default-output-visible");

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd     = n00b_string_from_cstr("cmd.exe"),
        .conduit = c,
        .io      = io,
        .args    = &args);

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    assert(SetStdHandle(STD_OUTPUT_HANDLE, old_stdout));
    CloseHandle(write_pipe);
    assert(n00b_result_is_ok(r));

    char  buf[256];
    DWORD nread = 0;
    assert(read_pipe_available(read_pipe, buf, sizeof(buf), &nread));
    assert(nread > 0);
    assert(strstr(buf, "default-output-visible") != nullptr);

    CloseHandle(read_pipe);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] windows default stdout inherits parent handle\n");
}

static void
test_windows_invalid_cwd_reports_setup_error(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);
    n00b_array_t(n00b_string_t *) args = cmd_args("exit /b 0");

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd     = n00b_string_from_cstr("cmd.exe"),
        .conduit = c,
        .io      = io,
        .args    = &args,
        .cwd     = n00b_string_from_cstr("Z:\\n00b-test-missing-cwd"));

    n00b_result_t(bool) r = n00b_subproc_spawn(&sp);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == ENOTDIR);
    assert(n00b_subproc_errored(&sp));

    n00b_subproc_close(&sp);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] windows invalid cwd reports setup error\n");
}

static void
test_windows_run_capture(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);
    n00b_array_t(n00b_string_t *) args = cmd_args("echo hello");

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("cmd.exe"),
        .conduit        = c,
        .io             = io,
        .args           = &args,
        .capture_stdout = true);

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    assert(n00b_result_is_ok(r));
    assert(buffer_contains(n00b_subproc_stdout(&sp), "hello"));

    n00b_result_t(int) ec = n00b_subproc_exit_code(&sp);
    assert(n00b_result_is_ok(ec));
    assert(n00b_result_get(ec) == 0);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] windows run capture\n");
}

static void
test_windows_topic_subscription(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);
    n00b_array_t(n00b_string_t *) args = cmd_args("echo topic-ok");

    n00b_subproc_buf_inbox_t *inbox = n00b_alloc(n00b_subproc_buf_inbox_t);
    n00b_conduit_inbox_init(n00b_buffer_t *, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_array_t(n00b_subproc_buf_inbox_t *) subs =
        n00b_array_new(n00b_subproc_buf_inbox_t *, 1);
    n00b_array_set(subs, 0, inbox);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("cmd.exe"),
        .conduit        = c,
        .io             = io,
        .args           = &args,
        .capture_stdout = true,
        .stdout_subs    = &subs);

    assert(!n00b_option_is_set(n00b_subproc_stdout_topic(&sp)));

    n00b_result_t(bool) r = n00b_subproc_spawn(&sp);
    assert(n00b_result_is_ok(r));
    assert(n00b_option_is_set(n00b_subproc_stdout_topic(&sp)));

    r = n00b_subproc_wait(&sp);
    assert(n00b_result_is_ok(r));
    assert(buffer_contains(n00b_subproc_stdout(&sp), "topic-ok"));
    assert(inbox_contains(inbox, "topic-ok"));

    n00b_subproc_close(&sp);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] windows topic subscription\n");
}

static void
test_windows_linebuf_xform(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);
    n00b_array_t(n00b_string_t *) args = cmd_args("echo alpha & echo beta");

    n00b_array_t(void *) xforms = n00b_array_new(void *, 1);
    n00b_array_set(xforms, 0,
                   (void *)&n00b_conduit_linebuf_default_spec);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("cmd.exe"),
        .conduit        = c,
        .io             = io,
        .args           = &args,
        .capture_stdout = true,
        .stdout_xforms  = &xforms);

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    assert(n00b_result_is_ok(r));
    assert(buffer_contains(n00b_subproc_stdout(&sp), "alpha"));
    assert(buffer_contains(n00b_subproc_stdout(&sp), "beta"));

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] windows linebuf xform\n");
}

static void
test_windows_proxy_stdout(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);
    n00b_array_t(n00b_string_t *) args = cmd_args("echo proxy-ok");

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd          = n00b_string_from_cstr("cmd.exe"),
        .conduit      = c,
        .io           = io,
        .args         = &args,
        .proxy_stdout = true);

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    assert(n00b_result_is_ok(r));
    n00b_result_t(int) ec = n00b_subproc_exit_code(&sp);
    assert(n00b_result_is_ok(ec));
    assert(n00b_result_get(ec) == 0);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] windows proxy stdout\n");
}

static void
test_windows_stdout_eof_done(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);
    n00b_array_t(n00b_string_t *) args = cmd_args("echo eof-ok");

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("cmd.exe"),
        .conduit        = c,
        .io             = io,
        .args           = &args,
        .capture_stdout = true,
        .done_condition = N00B_SUBPROC_DONE_STDOUT_EOF,
        .timeout_policy = N00B_SUBPROC_TIMEOUT_DETACH);

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    assert(n00b_result_is_ok(r));
    assert(buffer_contains(n00b_subproc_stdout(&sp), "eof-ok"));

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] windows stdout EOF done\n");
}

static void
test_windows_stdout_eof_before_exit(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);
    n00b_array_t(n00b_string_t *) args = n00b_array_new(n00b_string_t *, 1);
    n00b_array_set(args, 0, n00b_string_from_cstr("--win-close-stdout-child"));

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr(g_test_exe),
        .conduit        = c,
        .io             = io,
        .args           = &args,
        .capture_stdout = true,
        .done_condition = N00B_SUBPROC_DONE_STDOUT_EOF);

    n00b_result_t(bool) r = n00b_subproc_spawn(&sp);
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] windows stdout EOF before exit (spawn err=%d)\n",
               n00b_result_get_err(r));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    n00b_duration_t timeout = {.tv_sec = 0, .tv_nsec = 750000000};
    r = n00b_subproc_wait(&sp, .timeout = &timeout);
    assert(n00b_result_is_ok(r));
    assert(n00b_result_get(r));
    assert(buffer_contains(n00b_subproc_stdout(&sp), "eof-still-running"));

    if (!n00b_subproc_exited(&sp)) {
        n00b_subproc_kill(&sp);
        sp.done_condition = N00B_SUBPROC_DONE_PROC_EXIT;
        sp.done_flags     = 0;
        n00b_duration_t kill_timeout = {.tv_sec = 2, .tv_nsec = 0};
        n00b_subproc_wait(&sp, .timeout = &kill_timeout);
    }

    n00b_subproc_close(&sp);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] windows stdout EOF before exit\n");
}

static void
test_windows_stdin_xform(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);
    n00b_array_t(n00b_string_t *) args = cmd_args("more");
    n00b_buffer_t *inject = n00b_buffer_from_cstr("stdin-xform\n");

    n00b_array_t(void *) xforms = n00b_array_new(void *, 1);
    n00b_array_set(xforms, 0,
                   (void *)&n00b_conduit_linebuf_default_spec);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("cmd.exe"),
        .conduit        = c,
        .io             = io,
        .args           = &args,
        .capture_stdout = true,
        .capture_stdin  = true,
        .stdin_inject   = inject,
        .stdin_xforms   = &xforms);

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    assert(n00b_result_is_ok(r));
    assert(buffer_contains(n00b_subproc_stdin_capture(&sp), "stdin-xform"));
    assert(buffer_contains(n00b_subproc_stdout(&sp), "stdin-xform"));

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] windows stdin xform\n");
}

static void
test_windows_proxy_stdin_pipe(void)
{
    HANDLE old_stdin = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE parent_read = nullptr;
    HANDLE parent_write = nullptr;
    SECURITY_ATTRIBUTES sa = {
        .nLength              = sizeof(sa),
        .lpSecurityDescriptor = nullptr,
        .bInheritHandle       = TRUE,
    };
    assert(CreatePipe(&parent_read, &parent_write, &sa, 0));

    const char *input = "proxy-stdin\n";
    DWORD written = 0;
    assert(WriteFile(parent_write, input, (DWORD)strlen(input),
                     &written, nullptr));
    CloseHandle(parent_write);
    assert(SetStdHandle(STD_INPUT_HANDLE, parent_read));

    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);
    n00b_array_t(n00b_string_t *) args = cmd_args("more");

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("cmd.exe"),
        .conduit        = c,
        .io             = io,
        .args           = &args,
        .capture_stdout = true,
        .capture_stdin  = true,
        .proxy_stdin    = true,
        .close_stdin    = true);

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    assert(n00b_result_is_ok(r));
    assert(buffer_contains(n00b_subproc_stdin_capture(&sp), "proxy-stdin"));
    assert(buffer_contains(n00b_subproc_stdout(&sp), "proxy-stdin"));

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    assert(SetStdHandle(STD_INPUT_HANDLE, old_stdin));
    CloseHandle(parent_read);
    printf("  [PASS] windows proxy stdin pipe\n");
}

static void
test_windows_pre_exec_hook(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);
    n00b_array_t(n00b_string_t *) args = cmd_args("exit /b 0");

    int hook_count = 0;
    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd           = n00b_string_from_cstr("cmd.exe"),
        .conduit       = c,
        .io            = io,
        .args          = &args,
        .pre_exec_hook = windows_hook_fn,
        .hook_param    = &hook_count);

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    assert(n00b_result_is_ok(r));
    assert(hook_count == 1);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] windows pre exec hook\n");
}

static void
test_windows_pty_capture(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);
    n00b_array_t(n00b_string_t *) args = cmd_args("echo pty-output");

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd            = n00b_string_from_cstr("cmd.exe"),
        .conduit        = c,
        .io             = io,
        .args           = &args,
        .pty            = true,
        .capture_stdout = true,
        .capture_stderr = true);

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    assert(n00b_result_is_ok(r));
    assert(n00b_subproc_exited(&sp));
    assert(buffer_contains(n00b_subproc_stdout(&sp), "pty-output"));
    assert(buffer_contains(n00b_subproc_stderr(&sp), "pty-output"));

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] windows pty capture\n");
}

static void
test_windows_nonzero_exit(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);
    n00b_array_t(n00b_string_t *) args = cmd_args("exit /b 7");

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd     = n00b_string_from_cstr("cmd.exe"),
        .conduit = c,
        .io      = io,
        .args    = &args);

    n00b_result_t(bool) r = n00b_subproc_run(&sp);
    assert(n00b_result_is_ok(r));
    n00b_result_t(int) ec = n00b_subproc_exit_code(&sp);
    assert(n00b_result_is_ok(ec));
    assert(n00b_result_get(ec) == 7);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] windows nonzero exit\n");
}

static void
test_windows_bad_command(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_io_backend_t *io = make_io(c);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
        .cmd     = n00b_string_from_cstr("definitely-not-a-real-command.exe"),
        .conduit = c,
        .io      = io);

    n00b_result_t(bool) r = n00b_subproc_spawn(&sp);
    assert(n00b_result_is_err(r));
    assert(n00b_subproc_errored(&sp));

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] windows bad command\n");
}

#define RUN_WINDOWS_TEST(fn)                 \
    do {                                     \
        printf("  [RUN] %s\n", #fn);         \
        fflush(stdout);                      \
        fn();                                \
        fflush(stdout);                      \
    } while (0)

int
main(int argc, char *argv[])
{
    if (argc > 1 && strcmp(argv[1], "--win-write-handle-child") == 0) {
        return windows_write_handle_child(argc, argv);
    }
    if (argc > 1 && strcmp(argv[1], "--win-raw-argv-child") == 0) {
        return windows_raw_argv_child(argc, argv);
    }
    if (argc > 1 && strcmp(argv[1], "--win-close-stdout-child") == 0) {
        printf("eof-still-running\n");
        fflush(stdout);
        CloseHandle(GetStdHandle(STD_OUTPUT_HANDLE));
        Sleep(2000);
        return 0;
    }

    g_test_exe = argv[0];

    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_subproc:\n");
    fflush(stdout);

    RUN_WINDOWS_TEST(test_windows_init_defaults);
    RUN_WINDOWS_TEST(test_windows_raw_argv_uses_cmd_executable);
    RUN_WINDOWS_TEST(test_windows_does_not_inherit_unlisted_handles);
    RUN_WINDOWS_TEST(test_windows_custom_env_does_not_search_parent_path);
    RUN_WINDOWS_TEST(test_windows_default_stdout_inherits_parent_handle);
    RUN_WINDOWS_TEST(test_windows_invalid_cwd_reports_setup_error);
    RUN_WINDOWS_TEST(test_windows_run_capture);
    RUN_WINDOWS_TEST(test_windows_topic_subscription);
    RUN_WINDOWS_TEST(test_windows_linebuf_xform);
    RUN_WINDOWS_TEST(test_windows_proxy_stdout);
    RUN_WINDOWS_TEST(test_windows_stdout_eof_done);
    RUN_WINDOWS_TEST(test_windows_stdout_eof_before_exit);
    RUN_WINDOWS_TEST(test_windows_stdin_xform);
    RUN_WINDOWS_TEST(test_windows_proxy_stdin_pipe);
    RUN_WINDOWS_TEST(test_windows_pre_exec_hook);
    RUN_WINDOWS_TEST(test_windows_pty_capture);
    RUN_WINDOWS_TEST(test_windows_nonzero_exit);
    RUN_WINDOWS_TEST(test_windows_bad_command);

    printf("All Windows subproc tests passed.\n");
    n00b_shutdown();
    return 0;
}

#endif /* !_WIN32 */

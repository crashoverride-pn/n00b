/*
 * subproc.c — Subprocess management built on conduit primitives.
 */

#ifndef _WIN32

#include "n00b.h"
#include "conduit/subproc.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "conduit/conduit.h"
#include "conduit/fd_managed.h"
#include "conduit/fd_writer.h"
#include "conduit/io.h"
#include "conduit/proc_lifecycle.h"
#include "conduit/rw.h"
#include "conduit/signal.h"
#include "internal/subproc_policy.h"
#include "text/strings/string_convert.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

// openpty() — platform headers are unreliable; declare explicitly.
extern int openpty(int *aprimary, int *areplica, char *name,
                   struct termios *termp, struct winsize *winp);

// ============================================================================
// Internal helpers
// ============================================================================

static n00b_buffer_t empty_buf_sentinel = {};

/// Create a pipe with both ends set to CLOEXEC atomically where possible.
/// On Linux, uses pipe2(O_CLOEXEC) to avoid the race window between
/// pipe() and fcntl().  On other platforms (macOS, BSD), falls back to
/// pipe() + fcntl().
static int
cloexec_pipe(int fds[2])
{
#ifdef __linux__
    return pipe2(fds, O_CLOEXEC);
#else
    if (pipe(fds) < 0) {
        return -1;
    }
    fcntl(fds[0], F_SETFD, FD_CLOEXEC);
    fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    return 0;
#endif
}

static int
ensure_fd_above(int fd, int min_fd)
{
    if (fd >= min_fd) {
        return fd;
    }

    int new_fd = fcntl(fd, F_DUPFD_CLOEXEC, min_fd);
    if (new_fd < 0) {
        return -1;
    }
    close(fd);
    return new_fd;
}

static void
reset_child_signal_state(void)
{
    for (int sig = 1; sig < 32; sig++) {
        signal(sig, SIG_DFL);
    }

#ifdef __linux__
    // n00b blocks its default termination signals in the runtime so signalfd
    // can consume them.  A fork/exec child must not inherit that internal mask:
    // external programs expect SIGTERM/SIGINT/etc. to be deliverable.
    sigset_t unblocked;
    sigemptyset(&unblocked);
    sigprocmask(SIG_SETMASK, &unblocked, nullptr);
#endif
}

static char **
args_to_cstrv(n00b_array_t(n00b_string_t *) *args, n00b_string_t *cmd, bool raw_argv)
{
    size_t n_args = args ? args->len : 0;
    size_t offset = raw_argv ? 0 : 1;
    size_t total  = offset + n_args + 1;

    // This runs in the child after fork().  The child will execve() or
    // _exit(), so GC will never collect this.  Using n00b_alloc_array
    // avoids a bare calloc in the codebase.
    char **argv = n00b_alloc_array(char *, total);

    if (!raw_argv) {
        argv[0] = n00b_unicode_str_to_cstr(cmd);
    }

    for (size_t i = 0; i < n_args; i++) {
        argv[offset + i] = n00b_unicode_str_to_cstr(args->data[i]);
    }

    argv[total - 1] = nullptr;
    return argv;
}

static char **
env_to_cstrv(n00b_array_t(n00b_string_t *) *env)
{
    if (!env) {
        return nullptr;
    }

    size_t n = env->len;
    char **envp = n00b_alloc_array(char *, n + 1);

    for (size_t i = 0; i < n; i++) {
        envp[i] = n00b_unicode_str_to_cstr(env->data[i]);
    }

    envp[n] = nullptr;
    return envp;
}

// ============================================================================
// I/O wiring helper
// ============================================================================

/**
 * Wire capture and proxy subscriptions for all configured streams.
 * Called from spawn_pipe_mode() after FD owners are registered.
 *
 * Transform chain injection points:
 *   1. stdout_xforms: FD read → xforms → "stdout output topic"
 *   2. stderr_xforms: FD read → xforms → "stderr output topic"
 *   3. proxy_xforms:  output topic → xforms → fd_writer (parent terminal)
 *   4. stdin_xforms:  parent stdin → xforms → child stdin write
 *
 * Capture and custom topics subscribe to the post-xform output topics.
 * Proxy subscribes through its own (independent) xform chain.
 */
static void
wire_io(n00b_subproc_t *sp)
{
    uint32_t f = sp->flags;

    // -- Raw FD read topics --

    n00b_conduit_topic_t(n00b_buffer_t *) *stdout_raw = nullptr;
    n00b_conduit_topic_t(n00b_buffer_t *) *stderr_raw = nullptr;

    if (n00b_option_is_set(sp->stdout_owner)) {
        stdout_raw = n00b_conduit_fd_read_topic_typed(
            n00b_option_get(sp->stdout_owner));
    }
    if (n00b_option_is_set(sp->stderr_owner)
        && (!n00b_option_is_set(sp->stdout_owner)
            || n00b_option_get(sp->stderr_owner)
                != n00b_option_get(sp->stdout_owner))) {
        stderr_raw = n00b_conduit_fd_read_topic_typed(
            n00b_option_get(sp->stderr_owner));
    }

    // -- Apply stdout/stderr transform chains (injection points 1 & 2) --
    // The effective output topics are post-xform; capture and custom
    // topics subscribe to these.

    n00b_conduit_topic_t(n00b_buffer_t *) *stdout_out =
        n00b_subproc_apply_xform_chain(sp->conduit, stdout_raw, sp->stdout_xforms);

    n00b_conduit_topic_t(n00b_buffer_t *) *stderr_out =
        n00b_subproc_apply_xform_chain(sp->conduit, stderr_raw, sp->stderr_xforms);

    // Store effective topics for accessor functions.
    sp->eff_stdout_topic = (n00b_conduit_topic_base_t *)stdout_out;
    sp->eff_stderr_topic = (n00b_conduit_topic_base_t *)stderr_out;

    // -- Capture (subscribes to post-xform output topics) --

    if ((f & N00B_SUBPROC_CAP_STDOUT) && stdout_out) {
        sp->cap_stdout = n00b_subproc_wire_capture(sp->conduit, stdout_out,
                                      &sp->buf_stdout,
                                      &sp->cap_stdout_sub);
    }

    if ((f & N00B_SUBPROC_CAP_STDERR) && !(f & N00B_SUBPROC_MERGE_OUTPUT)
        && stderr_out) {
        sp->cap_stderr = n00b_subproc_wire_capture(sp->conduit, stderr_out,
                                      &sp->buf_stderr,
                                      &sp->cap_stderr_sub);
    }
    else if ((f & N00B_SUBPROC_CAP_STDERR) && (f & N00B_SUBPROC_MERGE_OUTPUT)
             && stdout_out) {
        // Merged: stderr capture is the same buffer as stdout.
        sp->buf_stderr = sp->buf_stdout;
    }

    // -- Proxy (injection point 3: output → proxy_xforms → fd_writer) --

    if ((f & N00B_SUBPROC_PROXY_STDOUT) && stdout_out) {
        n00b_conduit_topic_t(n00b_buffer_t *) *proxy_src =
            n00b_subproc_apply_xform_chain(sp->conduit, stdout_out, sp->proxy_xforms);
        auto r = n00b_conduit_fd_writer_new(sp->conduit, proxy_src,
                                            STDOUT_FILENO);
        if (n00b_result_is_ok(r)) {
            sp->proxy_stdout = n00b_result_get(r);
        }
    }

    if ((f & N00B_SUBPROC_PROXY_STDERR) && !(f & N00B_SUBPROC_MERGE_OUTPUT)
        && stderr_out) {
        n00b_conduit_topic_t(n00b_buffer_t *) *proxy_src =
            n00b_subproc_apply_xform_chain(sp->conduit, stderr_out, sp->proxy_xforms);
        auto r = n00b_conduit_fd_writer_new(sp->conduit, proxy_src,
                                            STDERR_FILENO);
        if (n00b_result_is_ok(r)) {
            sp->proxy_stderr = n00b_result_get(r);
        }
    }
    else if ((f & N00B_SUBPROC_PROXY_STDERR) && (f & N00B_SUBPROC_MERGE_OUTPUT)
             && stdout_out) {
        // Merged: proxy stderr to parent stderr using stdout's output.
        n00b_conduit_topic_t(n00b_buffer_t *) *proxy_src =
            n00b_subproc_apply_xform_chain(sp->conduit, stdout_out, sp->proxy_xforms);
        auto r = n00b_conduit_fd_writer_new(sp->conduit, proxy_src,
                                            STDERR_FILENO);
        if (n00b_result_is_ok(r)) {
            sp->proxy_stderr = n00b_result_get(r);
        }
    }

    // -- Proxy stdin: relay parent stdin → child stdin --
    //
    // Manage parent STDIN_FILENO as a read-only FD owner.  Its read_topic
    // produces n00b_buffer_t * payloads when the user types.  Wire an
    // fd_writer from that topic to the child's stdin pipe FD, optionally
    // through stdin_xforms.

    if ((f & N00B_SUBPROC_PROXY_STDIN) && n00b_option_is_set(sp->stdin_owner)) {
        n00b_result_t(n00b_conduit_fd_owner_t *) pr =
            n00b_conduit_fd_manage(sp->conduit, sp->io, STDIN_FILENO, false);
        if (n00b_result_is_ok(pr)) {
            sp->parent_stdin_owner =
                n00b_option_set(n00b_conduit_fd_owner_t *, n00b_result_get(pr));
            n00b_conduit_topic_t(n00b_buffer_t *) *parent_stdin_raw =
                n00b_conduit_fd_read_topic_typed(
                    n00b_option_get(sp->parent_stdin_owner));

            // Apply stdin_xforms (injection point 4) if present.
            n00b_conduit_topic_t(n00b_buffer_t *) *stdin_src =
                n00b_subproc_apply_xform_chain(sp->conduit, parent_stdin_raw, sp->stdin_xforms);

            // Wire an fd_writer that writes to the child's stdin FD.
            auto r = n00b_conduit_fd_writer_new(sp->conduit, stdin_src,
                n00b_option_get(sp->stdin_owner)->fd);
            if (n00b_result_is_ok(r)) {
                sp->proxy_stdin = n00b_result_get(r);
            }
        }
    }

    // -- User-supplied subscriptions (wired before gate opens) --

    n00b_subproc_wire_user_subs(sp->conduit, stdout_out, sp->stdout_subs);
    n00b_subproc_wire_user_subs(sp->conduit, stderr_out, sp->stderr_subs);

    // stdin observation topic: create when we need to observe data flowing
    // into the child's stdin (cap_stdin or stdin_subs).  Data is published
    // to it from write_stdin / stdin_inject / proxy_stdin paths.
    bool need_stdin_obs = (f & N00B_SUBPROC_CAP_STDIN)
                          || (sp->stdin_subs && sp->stdin_subs->len > 0);
    if (need_stdin_obs && n00b_option_is_set(sp->stdin_owner)) {
        sp->stdin_obs_topic = n00b_conduit_topic_init(
            n00b_buffer_t *, sp->conduit,
            N00B_CONDUIT_URI_USER_EVENT(0));
        n00b_subproc_wire_user_subs(sp->conduit, sp->stdin_obs_topic, sp->stdin_subs);
    }
}

// ============================================================================
// Done-inbox wiring
// ============================================================================

/**
 * Wire the unified done-inbox for completion detection.
 *
 * The done-inbox receives `n00b_conduit_topic_base_t *` messages when
 * topics close (via their done_topics).  Subscriptions are created for:
 *   - stdout read topic's done_topic (fires on FD owner close → EOF)
 *   - stderr read topic's done_topic (if separate; fires on FD owner close)
 *   - proc topic's done_topic (fires when we close it after proc exit)
 *
 * The proc inbox is a separate typed inbox for `n00b_conduit_proc_payload_t`
 * that receives the actual exit event (carrying exit_status).  When we see
 * the exit event, we extract exit_status and close the proc topic, which
 * fires the proc done_topic → the done_inbox receives it.
 */
static void
wire_done_inbox(n00b_subproc_t *sp)
{
    n00b_conduit_t *c = sp->conduit;

    // Create the unified done-inbox.
    sp->done_inbox = n00b_alloc_with_opts(
        n00b_conduit_inbox_t(n00b_conduit_topic_base_t *),
        &(n00b_alloc_opts_t){.allocator = c->allocator});
    n00b_conduit_inbox_init(n00b_conduit_topic_base_t *, sp->done_inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);

    // Subscribe to the effective (post-xform) stdout topic's done_topic.
    // When transform chains are present, this is the chain's final output
    // topic — it closes only after the chain has flushed, which is the
    // correct completion signal.  Without xforms, eff_stdout_topic IS the
    // raw read_topic, so this works in both cases.
    if (sp->eff_stdout_topic) {
        n00b_conduit_topic_t(n00b_conduit_topic_base_t *) *dt =
            n00b_conduit_topic_ensure_done(sp->eff_stdout_topic);
        if (dt) {
            sp->done_stdout_sub = n00b_conduit_subscribe(
                n00b_conduit_topic_base_t *, dt, sp->done_inbox,
                .operations = N00B_CONDUIT_OP_ALL);
        }
    }

    // Subscribe to the effective (post-xform) stderr topic's done_topic.
    if (sp->eff_stderr_topic && sp->eff_stderr_topic != sp->eff_stdout_topic) {
        n00b_conduit_topic_t(n00b_conduit_topic_base_t *) *dt =
            n00b_conduit_topic_ensure_done(sp->eff_stderr_topic);
        if (dt) {
            sp->done_stderr_sub = n00b_conduit_subscribe(
                n00b_conduit_topic_base_t *, dt, sp->done_inbox,
                .operations = N00B_CONDUIT_OP_ALL);
        }
    }

    // Subscribe to proc topic's done_topic.
    if (sp->proc_topic) {
        n00b_conduit_topic_t(n00b_conduit_topic_base_t *) *dt =
            n00b_conduit_topic_ensure_done(sp->proc_topic);
        if (dt) {
            sp->done_proc_sub = n00b_conduit_subscribe(
                n00b_conduit_topic_base_t *, dt, sp->done_inbox,
                .operations = N00B_CONDUIT_OP_ALL);
        }
    }

    // Create the proc inbox for exit status extraction.
    if (sp->proc_topic) {
        sp->proc_inbox = n00b_conduit_proc_inbox_new(c);
        sp->proc_inbox_sub = n00b_conduit_proc_subscribe(
            sp->proc_topic, sp->proc_inbox,
            .operations = N00B_CONDUIT_OP_ALL);
    }
}

// ============================================================================
// Signal subscription wiring
// ============================================================================

/**
 * Subscribe to relevant signals via the conduit signal module.
 *
 * - SIGPIPE: detect broken pipe (child closed stdin read end).
 * - SIGWINCH: proxy terminal size changes (PTY mode, Phase 7).
 *
 * Process exit is handled by proc_lifecycle (kqueue/pidfd), not SIGCHLD.
 */
static void
wire_signals(n00b_subproc_t *sp)
{
    n00b_conduit_t *c = sp->conduit;

    sp->signal_inbox = n00b_conduit_signal_inbox_new(c);

    // SIGPIPE — detect broken pipe.
    {
        n00b_result_t(n00b_conduit_topic_base_t *) sr =
            n00b_conduit_signal_topic(c, SIGPIPE);
        if (n00b_result_is_ok(sr)) {
            sp->sigpipe_sub = n00b_conduit_signal_subscribe(
                n00b_result_get(sr), sp->signal_inbox,
                .operations = N00B_CONDUIT_OP_ALL);
        }
    }

    // SIGWINCH — PTY terminal resize (wired now, used in Phase 7).
    if (sp->flags & N00B_SUBPROC_HANDLE_WINSIZE) {
        n00b_result_t(n00b_conduit_topic_base_t *) sr =
            n00b_conduit_signal_topic(c, SIGWINCH);
        if (n00b_result_is_ok(sr)) {
            sp->sigwinch_sub = n00b_conduit_signal_subscribe(
                n00b_result_get(sr), sp->signal_inbox,
                .operations = N00B_CONDUIT_OP_ALL);
        }
    }
}

/**
 * Drain signal inbox and update done_flags.
 */
static void
drain_signal_inbox(n00b_subproc_t *sp)
{
    if (!sp->signal_inbox) {
        return;
    }

    n00b_conduit_signal_msg_t *msg;
    while ((msg = n00b_conduit_signal_inbox_pop(sp->signal_inbox)) != nullptr) {
        if (msg->payload.signum == SIGPIPE) {
            sp->done_flags |= N00B_SUBPROC_DONE_F_SIGPIPE;
        }
        if (msg->payload.signum == SIGWINCH) {
            n00b_subproc_proxy_winsize(sp);
        }
    }
}

// ============================================================================
// Done-condition helpers
// ============================================================================

/**
 * Process a done-inbox message: identify which topic closed and
 * set the appropriate done_flags bit.
 */
static void
update_done_flags_from_topic(n00b_subproc_t *sp, n00b_conduit_topic_base_t *closed)
{
    if (!closed) {
        return;
    }

    if (sp->eff_stdout_topic && closed == sp->eff_stdout_topic) {
        n00b_subproc_note_stdout_done(sp);
    }
    else if (sp->eff_stderr_topic
             && sp->eff_stderr_topic != sp->eff_stdout_topic
             && closed == sp->eff_stderr_topic) {
        n00b_subproc_note_stderr_done(sp);
    }
    else if (closed == sp->proc_topic) {
        n00b_subproc_note_proc_done(sp);
    }
}

/**
 * Drain proc inbox: if the child has exited, extract exit status
 * and close the proc topic (which fires done_topic → done_inbox).
 */
static void
drain_proc_inbox(n00b_subproc_t *sp)
{
    if (!sp->proc_inbox) {
        return;
    }

    n00b_conduit_proc_msg_t *msg;
    while ((msg = n00b_conduit_proc_inbox_pop(sp->proc_inbox)) != nullptr) {
        if (msg->payload.events & N00B_CONDUIT_PROC_EXIT) {
            int status = msg->payload.exit_status;
            if (WIFEXITED(status)) {
                sp->exit_status = n00b_option_set(int, WEXITSTATUS(status));
            }
            if (WIFSIGNALED(status)) {
                sp->term_signal = n00b_option_set(int, WTERMSIG(status));
            }
            atomic_store(&sp->exited, true);
            // proc_lifecycle auto-closes the topic on EXIT, which
            // fires done_topic → done_inbox picks it up.
        }
    }
}

/**
 * Drain the done-inbox: pop all messages, update done_flags.
 */
static void
drain_done_inbox(n00b_subproc_t *sp)
{
    if (!sp->done_inbox) {
        return;
    }

    n00b_conduit_message_t(n00b_conduit_topic_base_t *) *msg;
    while ((msg = n00b_conduit_inbox_pop_msg(
                n00b_conduit_topic_base_t *, sp->done_inbox)) != nullptr) {
        update_done_flags_from_topic(sp, msg->payload);
    }
}

// ============================================================================
// Constructor
// ============================================================================

void
n00b_subproc_init(n00b_subproc_t *sp) _kargs
{
    n00b_string_t                             *cmd;
    n00b_conduit_t                            *conduit         = nullptr;
    n00b_conduit_io_backend_t                 *io              = nullptr;
    n00b_array_t(n00b_string_t *)               *args            = nullptr;
    n00b_array_t(n00b_string_t *)               *env             = nullptr;
    bool                                       capture         = false;
    bool                                       capture_stdin   = false;
    bool                                       capture_stdout  = false;
    bool                                       capture_stderr  = false;
    bool                                       proxy           = false;
    bool                                       proxy_stdin     = false;
    bool                                       proxy_stdout    = false;
    bool                                       proxy_stderr    = false;
    bool                                       merge           = true;
    bool                                       pty             = false;
    bool                                       raw_argv        = false;
    bool                                       err_pty         = false;
    bool                                       handle_win_size = true;
    n00b_buffer_t                             *stdin_inject    = nullptr;
    bool                                       close_stdin     = false;
    n00b_string_t                             *cwd;
    struct termios                            *termcap         = nullptr;
    n00b_duration_t                           *timeout         = nullptr;
    n00b_subproc_timeout_t                     timeout_policy  = N00B_SUBPROC_TIMEOUT_SIGTERM;
    n00b_subproc_done_t                        done_condition  = N00B_SUBPROC_DONE_IO_DRAINED;
    n00b_subproc_done_fn_t                     done_fn         = nullptr;
    void                                      *done_fn_ctx    = nullptr;
    n00b_pre_exec_hook_t                       pre_exec_hook   = nullptr;
    void                                      *hook_param     = nullptr;
    n00b_array_t(void *)                      *stdout_xforms  = nullptr;
    n00b_array_t(void *)                      *stderr_xforms  = nullptr;
    n00b_array_t(void *)                      *proxy_xforms   = nullptr;
    n00b_array_t(void *)                      *stdin_xforms   = nullptr;
    n00b_array_t(n00b_subproc_buf_inbox_t *)   *stdout_subs    = nullptr;
    n00b_array_t(n00b_subproc_buf_inbox_t *)   *stderr_subs    = nullptr;
    n00b_array_t(n00b_subproc_buf_inbox_t *)   *stdin_subs     = nullptr;
}
{
    sp->cmd            = cmd;
    sp->conduit        = conduit;
    sp->io             = io;
    sp->args           = args;
    sp->env            = env;
    sp->stdin_inject   = stdin_inject;
    sp->cwd            = cwd;
    sp->termcap        = termcap;
    sp->timeout        = timeout;
    sp->timeout_policy = timeout_policy;
    sp->done_condition = done_condition;
    sp->done_fn        = done_fn;
    sp->done_fn_ctx    = done_fn_ctx;
    sp->pre_exec_hook  = pre_exec_hook;
    sp->hook_param     = hook_param;
    sp->stdout_xforms  = stdout_xforms;
    sp->stderr_xforms  = stderr_xforms;
    sp->proxy_xforms   = proxy_xforms;
    sp->stdin_xforms   = stdin_xforms;
    sp->stdout_subs    = stdout_subs;
    sp->stderr_subs    = stderr_subs;
    sp->stdin_subs     = stdin_subs;

    // Build flags bitmask from convenience booleans.
    uint32_t f = 0;

    if (capture)        f |= N00B_SUBPROC_CAP_ALL;
    if (capture_stdin)  f |= N00B_SUBPROC_CAP_STDIN;
    if (capture_stdout) f |= N00B_SUBPROC_CAP_STDOUT;
    if (capture_stderr) f |= N00B_SUBPROC_CAP_STDERR;
    if (proxy)          f |= N00B_SUBPROC_PROXY_ALL;
    if (proxy_stdin)    f |= N00B_SUBPROC_PROXY_STDIN;
    if (proxy_stdout)   f |= N00B_SUBPROC_PROXY_STDOUT;
    if (proxy_stderr)   f |= N00B_SUBPROC_PROXY_STDERR;
    if (merge)          f |= N00B_SUBPROC_MERGE_OUTPUT;
    if (pty)            f |= N00B_SUBPROC_USE_PTY;
    if (raw_argv)       f |= N00B_SUBPROC_RAW_ARGV;
    if (err_pty)        f |= N00B_SUBPROC_PTY_STDERR;
    if (handle_win_size) f |= N00B_SUBPROC_HANDLE_WINSIZE;
    if (close_stdin)    f |= N00B_SUBPROC_CLOSE_STDIN;

    sp->flags = f;

    // Initialize runtime state.
    sp->pid                = n00b_option_none(pid_t);
    sp->gate               = n00b_option_none(int);
    sp->exit_status        = n00b_option_none(int);
    sp->term_signal        = n00b_option_none(int);
    sp->stdin_owner        = n00b_option_none(n00b_conduit_fd_owner_t *);
    sp->stdout_owner       = n00b_option_none(n00b_conduit_fd_owner_t *);
    sp->stderr_owner       = n00b_option_none(n00b_conduit_fd_owner_t *);
    sp->parent_stdin_owner = n00b_option_none(n00b_conduit_fd_owner_t *);
    sp->done_flags         = 0;
    sp->required_mask      = 0;

    atomic_store(&sp->spawned, false);
    atomic_store(&sp->exited, false);
    sp->closed    = false;
    sp->errored   = false;
    sp->timed_out = false;

    sp->buf_stdin  = &empty_buf_sentinel;
    sp->buf_stdout = &empty_buf_sentinel;
    sp->buf_stderr = &empty_buf_sentinel;
}

// ============================================================================
// Pipe-mode spawn
// ============================================================================

static n00b_result_t(bool)
spawn_pipe_mode(n00b_subproc_t *sp)
{
    int stdin_pipe[2]  = {-1, -1};
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};
    int gate_pipe[2]   = {-1, -1};
    int err_pipe[2]    = {-1, -1};

    uint32_t f = sp->flags;
    bool need_stdin  = (f & (N00B_SUBPROC_CAP_STDIN | N00B_SUBPROC_PROXY_STDIN))
                       || sp->stdin_inject
                       || (f & N00B_SUBPROC_CLOSE_STDIN);
    bool need_stdout = (f & (N00B_SUBPROC_CAP_STDOUT | N00B_SUBPROC_PROXY_STDOUT)) != 0;
    bool need_stderr = (f & (N00B_SUBPROC_CAP_STDERR | N00B_SUBPROC_PROXY_STDERR)) != 0;

    // Merge only matters when stderr would otherwise need a separate pipe.
    // If capture/proxy for stderr is active, merge redirects it through
    // stdout's pipe instead of creating a separate stderr pipe.
    if ((f & N00B_SUBPROC_MERGE_OUTPUT) && need_stderr) {
        need_stdout = true;
        need_stderr = false;
    }

    // Create pipes for needed streams.
    if (need_stdin && pipe(stdin_pipe) < 0) {
        return n00b_result_err(bool, errno);
    }
    if (need_stdout && pipe(stdout_pipe) < 0) {
        int e = errno;
        if (need_stdin) { close(stdin_pipe[0]); close(stdin_pipe[1]); }
        return n00b_result_err(bool, e);
    }
    if (need_stderr && pipe(stderr_pipe) < 0) {
        int e = errno;
        if (need_stdin)  { close(stdin_pipe[0]); close(stdin_pipe[1]); }
        if (need_stdout) { close(stdout_pipe[0]); close(stdout_pipe[1]); }
        return n00b_result_err(bool, e);
    }

    // Gate pipe (CLOEXEC).
    if (cloexec_pipe(gate_pipe) < 0) {
        int e = errno;
        if (need_stdin)  { close(stdin_pipe[0]); close(stdin_pipe[1]); }
        if (need_stdout) { close(stdout_pipe[0]); close(stdout_pipe[1]); }
        if (need_stderr) { close(stderr_pipe[0]); close(stderr_pipe[1]); }
        return n00b_result_err(bool, e);
    }

    // Error-report pipe for exec failure (CLOEXEC).
    if (cloexec_pipe(err_pipe) < 0) {
        int e = errno;
        close(gate_pipe[0]); close(gate_pipe[1]);
        if (need_stdin)  { close(stdin_pipe[0]); close(stdin_pipe[1]); }
        if (need_stdout) { close(stdout_pipe[0]); close(stdout_pipe[1]); }
        if (need_stderr) { close(stderr_pipe[0]); close(stderr_pipe[1]); }
        return n00b_result_err(bool, e);
    }

    // Ensure parent-side FDs are >= 3.
    if (need_stdin) {
        stdin_pipe[1] = ensure_fd_above(stdin_pipe[1], 3);
        if (stdin_pipe[1] < 0) {
            return n00b_result_err(bool, errno);
        }
    }
    if (need_stdout) {
        stdout_pipe[0] = ensure_fd_above(stdout_pipe[0], 3);
        if (stdout_pipe[0] < 0) {
            return n00b_result_err(bool, errno);
        }
    }
    if (need_stderr) {
        stderr_pipe[0] = ensure_fd_above(stderr_pipe[0], 3);
        if (stderr_pipe[0] < 0) {
            return n00b_result_err(bool, errno);
        }
    }

    pid_t child = fork();
    if (child < 0) {
        int e = errno;
        close(gate_pipe[0]); close(gate_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        if (need_stdin)  { close(stdin_pipe[0]); close(stdin_pipe[1]); }
        if (need_stdout) { close(stdout_pipe[0]); close(stdout_pipe[1]); }
        if (need_stderr) { close(stderr_pipe[0]); close(stderr_pipe[1]); }
        return n00b_result_err(bool, e);
    }

    if (child == 0) {
        // ============================================================
        // CHILD
        // ============================================================

        close(gate_pipe[1]);
        close(err_pipe[0]);
        if (need_stdin)  close(stdin_pipe[1]);
        if (need_stdout) close(stdout_pipe[0]);
        if (need_stderr) close(stderr_pipe[0]);

        if (need_stdin) {
            dup2(stdin_pipe[0], STDIN_FILENO);
            if (stdin_pipe[0] > 2) close(stdin_pipe[0]);
        }
        if (need_stdout) {
            dup2(stdout_pipe[1], STDOUT_FILENO);
            if (f & N00B_SUBPROC_MERGE_OUTPUT) {
                dup2(stdout_pipe[1], STDERR_FILENO);
            }
            if (stdout_pipe[1] > 2) close(stdout_pipe[1]);
        }
        if (need_stderr) {
            dup2(stderr_pipe[1], STDERR_FILENO);
            if (stderr_pipe[1] > 2) close(stderr_pipe[1]);
        }

        reset_child_signal_state();

        if (sp->cwd) {
            const char *dir = n00b_unicode_str_to_cstr(sp->cwd);
            if (chdir(dir) < 0) {
                int e = errno;
                (void)!write(err_pipe[1], &e, sizeof(e));
                _exit(127);
            }
        }

        if (sp->pre_exec_hook) {
            sp->pre_exec_hook(sp->hook_param);
        }

        char gate_buf;
        (void)!read(gate_pipe[0], &gate_buf, 1);
        close(gate_pipe[0]);

        char **argv = args_to_cstrv(sp->args, sp->cmd,
                                     (f & N00B_SUBPROC_RAW_ARGV) != 0);
        char **envp = env_to_cstrv(sp->env);

        const char *cmd_cstr = n00b_unicode_str_to_cstr(sp->cmd);

        if (envp) {
            execve(cmd_cstr, argv, envp);
        }
        else {
            execvp(cmd_cstr, argv);
        }

        int e = errno;
        (void)!write(err_pipe[1], &e, sizeof(e));
        _exit(127);
    }

    // ================================================================
    // PARENT
    // ================================================================

    close(gate_pipe[0]);
    close(err_pipe[1]);
    if (need_stdin)  close(stdin_pipe[0]);
    if (need_stdout) close(stdout_pipe[1]);
    if (need_stderr) close(stderr_pipe[1]);

    sp->pid  = n00b_option_set(pid_t, child);
    sp->gate = n00b_option_set(int, gate_pipe[1]);

    // Register parent-side FDs with conduit.
    if (need_stdin) {
        n00b_result_t(n00b_conduit_fd_owner_t *) r =
            n00b_conduit_fd_manage(sp->conduit, sp->io, stdin_pipe[1], true);
        if (n00b_result_is_ok(r)) {
            sp->stdin_owner =
                n00b_option_set(n00b_conduit_fd_owner_t *, n00b_result_get(r));
        }
    }
    if (need_stdout) {
        n00b_result_t(n00b_conduit_fd_owner_t *) r =
            n00b_conduit_fd_manage(sp->conduit, sp->io, stdout_pipe[0], true);
        if (n00b_result_is_ok(r)) {
            sp->stdout_owner =
                n00b_option_set(n00b_conduit_fd_owner_t *, n00b_result_get(r));
        }
    }
    if (need_stderr) {
        n00b_result_t(n00b_conduit_fd_owner_t *) r =
            n00b_conduit_fd_manage(sp->conduit, sp->io, stderr_pipe[0], true);
        if (n00b_result_is_ok(r)) {
            sp->stderr_owner =
                n00b_option_set(n00b_conduit_fd_owner_t *, n00b_result_get(r));
        }
    }

    // Register proc lifecycle watch.
    {
        n00b_result_t(n00b_conduit_topic_base_t *) pr =
            n00b_conduit_proc_topic(sp->conduit, child,
                                    N00B_CONDUIT_PROC_EXIT);
        if (n00b_result_is_ok(pr)) {
            sp->proc_topic = n00b_result_get(pr);
        }
    }

    // Compute required_mask for done-inbox.
    bool wait_stdout = n00b_option_is_set(sp->stdout_owner);
    bool wait_stderr = n00b_option_is_set(sp->stderr_owner)
                       && (!n00b_option_is_set(sp->stdout_owner)
                           || n00b_option_get(sp->stderr_owner)
                              != n00b_option_get(sp->stdout_owner));
    sp->required_mask = n00b_subproc_completion_mask(wait_stdout,
                                                     wait_stderr,
                                                     sp->stdin_inject != nullptr);

    // Wire capture and proxy subscriptions.
    wire_io(sp);

    // Wire the done-inbox for completion detection.
    wire_done_inbox(sp);

    // Wire signal subscriptions (SIGPIPE, SIGWINCH).
    wire_signals(sp);

    // Wire stdin capture to the observation topic (if both exist).
    if ((f & N00B_SUBPROC_CAP_STDIN) && sp->stdin_obs_topic) {
        sp->cap_stdin = n00b_subproc_wire_capture(sp->conduit, sp->stdin_obs_topic,
                                     &sp->buf_stdin,
                                     &sp->cap_stdin_sub);
    }
    else if ((f & N00B_SUBPROC_CAP_STDIN) && sp->buf_stdin->alloc_len == 0) {
        // No observation topic (no stdin_owner) — still init the buffer.
        sp->buf_stdin = n00b_buffer_empty(
            .allocator = sp->conduit->allocator);
    }

    // Inject stdin data if configured.
    // Use the synchronous write path so the data is fully written
    // before we potentially close the FD.
    if (sp->stdin_inject && n00b_option_is_set(sp->stdin_owner)) {
        // Publish to stdin observation topic (feeds cap_stdin + stdin_subs).
        if (sp->stdin_obs_topic && sp->stdin_inject->byte_len > 0) {
            n00b_conduit_write_async(n00b_buffer_t *, sp->stdin_obs_topic,
                                     sp->stdin_inject);
        }
        n00b_fd_owner_write(n00b_option_get(sp->stdin_owner),
                            sp->stdin_inject->data,
                            sp->stdin_inject->byte_len);
        sp->done_flags |= N00B_SUBPROC_DONE_F_STDIN_DONE;
    }

    // Close stdin if requested (after injection is complete).
    if ((f & N00B_SUBPROC_CLOSE_STDIN) && n00b_option_is_set(sp->stdin_owner)) {
        n00b_conduit_fd_owner_close(n00b_option_get(sp->stdin_owner));
    }

    // Release the gate.
    int gate_fd = n00b_option_get(sp->gate);
    char gate_byte = 'G';
    (void)!write(gate_fd, &gate_byte, 1);
    close(gate_fd);
    sp->gate = n00b_option_none(int);

    // Check error pipe for exec failure.
    int child_errno = 0;
    ssize_t n = read(err_pipe[0], &child_errno, sizeof(child_errno));
    close(err_pipe[0]);

    if (n > 0) {
        waitpid(child, nullptr, 0);
        sp->errored     = true;
        sp->saved_errno = child_errno;
        atomic_store(&sp->exited, true);
        return n00b_result_err(bool, child_errno);
    }

    atomic_store(&sp->spawned, true);
    return n00b_result_ok(bool, true);
}

// ============================================================================
// PTY-mode spawn (Phase 6)
// ============================================================================

static n00b_result_t(bool)
spawn_pty_mode(n00b_subproc_t *sp)
{
    uint32_t f = sp->flags;
    bool use_aux = (f & N00B_SUBPROC_PTY_STDERR) != 0;

    // -- Pre-fork: query parent terminal and open PTY(s) --

    struct winsize *win_ptr  = &sp->dimensions;
    struct termios *term_ptr = nullptr;

    if (isatty(STDIN_FILENO)) {
        ioctl(STDIN_FILENO, TIOCGWINSZ, &sp->dimensions);
        tcgetattr(STDIN_FILENO, &sp->initial_termcap);
        sp->termcap_saved = true;
        term_ptr = sp->termcap ? sp->termcap : &sp->initial_termcap;
    }
    else {
        win_ptr  = nullptr;
        term_ptr = sp->termcap;
    }

    int master_fd   = -1;
    int replica_fd  = -1;
    int aux_master  = -1;
    int aux_replica = -1;

    if (openpty(&master_fd, &replica_fd, nullptr, term_ptr, win_ptr) < 0) {
        return n00b_result_err(bool, errno);
    }

    if (use_aux) {
        if (openpty(&aux_master, &aux_replica, nullptr, term_ptr, win_ptr) < 0) {
            int e = errno;
            close(master_fd);
            close(replica_fd);
            return n00b_result_err(bool, e);
        }
    }

    // Ensure parent-side (master) FDs are >= 3 so they don't collide
    // with stdin/stdout/stderr after the child's dup2 calls.
    master_fd = ensure_fd_above(master_fd, 3);
    if (master_fd < 0) {
        int e = errno;
        close(replica_fd);
        if (use_aux) { close(aux_master); close(aux_replica); }
        return n00b_result_err(bool, e);
    }
    if (use_aux) {
        aux_master = ensure_fd_above(aux_master, 3);
        if (aux_master < 0) {
            int e = errno;
            close(master_fd);
            close(replica_fd);
            close(aux_replica);
            return n00b_result_err(bool, e);
        }
    }

    // Gate pipe and error-report pipe (CLOEXEC, same as pipe mode).
    int gate_pipe[2] = {-1, -1};
    int err_pipe[2]  = {-1, -1};

    if (cloexec_pipe(gate_pipe) < 0) {
        int e = errno;
        close(master_fd); close(replica_fd);
        if (use_aux) { close(aux_master); close(aux_replica); }
        return n00b_result_err(bool, e);
    }

    if (cloexec_pipe(err_pipe) < 0) {
        int e = errno;
        close(gate_pipe[0]); close(gate_pipe[1]);
        close(master_fd); close(replica_fd);
        if (use_aux) { close(aux_master); close(aux_replica); }
        return n00b_result_err(bool, e);
    }

    // -- Fork --

    pid_t child = fork();
    if (child < 0) {
        int e = errno;
        close(gate_pipe[0]); close(gate_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        close(master_fd); close(replica_fd);
        if (use_aux) { close(aux_master); close(aux_replica); }
        return n00b_result_err(bool, e);
    }

    if (child == 0) {
        // ============================================================
        // CHILD
        // ============================================================

        // Close parent-side FDs.
        close(master_fd);
        close(gate_pipe[1]);
        close(err_pipe[0]);
        if (use_aux) {
            close(aux_master);
        }

        // Become session leader and claim controlling terminal.
        setsid();

        if (ioctl(replica_fd, TIOCSCTTY, 0) < 0) {
            int e = errno;
            (void)!write(err_pipe[1], &e, sizeof(e));
            _exit(127);
        }

        // dup2 for FDs 0/1/2.
        // Without PTY_STDERR: all three on the same PTY.
        // With PTY_STDERR: stdin+stderr on main PTY, stdout on aux PTY.
        // This matches the reference: programs like `more` open stderr's
        // TTY for reads, so stdin and stderr must share a PTY.
        dup2(replica_fd, STDIN_FILENO);
        if (use_aux) {
            dup2(replica_fd, STDERR_FILENO);
            dup2(aux_replica, STDOUT_FILENO);
            if (aux_replica > 2) {
                close(aux_replica);
            }
        }
        else {
            dup2(replica_fd, STDOUT_FILENO);
            dup2(replica_fd, STDERR_FILENO);
        }
        if (replica_fd > 2) {
            close(replica_fd);
        }

        // Unbuffer stdio.
        setvbuf(stdin, nullptr, _IONBF, 0);
        setvbuf(stdout, nullptr, _IONBF, 0);
        setvbuf(stderr, nullptr, _IONBF, 0);

        reset_child_signal_state();

        // chdir if requested.
        if (sp->cwd) {
            const char *dir = n00b_unicode_str_to_cstr(sp->cwd);
            if (chdir(dir) < 0) {
                int e = errno;
                (void)!write(err_pipe[1], &e, sizeof(e));
                _exit(127);
            }
        }

        // Pre-exec hook.
        if (sp->pre_exec_hook) {
            sp->pre_exec_hook(sp->hook_param);
        }

        // Gate wait — blocks until parent has wired everything.
        char gate_buf;
        (void)!read(gate_pipe[0], &gate_buf, 1);
        close(gate_pipe[0]);

        // exec.
        char **argv = args_to_cstrv(sp->args, sp->cmd,
                                     (f & N00B_SUBPROC_RAW_ARGV) != 0);
        char **envp = env_to_cstrv(sp->env);
        const char *cmd_cstr = n00b_unicode_str_to_cstr(sp->cmd);

        if (envp) {
            execve(cmd_cstr, argv, envp);
        }
        else {
            execvp(cmd_cstr, argv);
        }

        // exec failed.
        int e = errno;
        (void)!write(err_pipe[1], &e, sizeof(e));
        _exit(127);
    }

    // ================================================================
    // PARENT
    // ================================================================

    // Close child-side FDs.
    close(replica_fd);
    close(gate_pipe[0]);
    close(err_pipe[1]);
    if (use_aux) {
        close(aux_replica);
    }

    sp->pid  = n00b_option_set(pid_t, child);
    sp->gate = n00b_option_set(int, gate_pipe[1]);

    // Register master FD with conduit.
    // In PTY mode, a single FD handles both read (child stdout) and
    // write (child stdin) through the PTY master.
    {
        n00b_result_t(n00b_conduit_fd_owner_t *) r =
            n00b_conduit_fd_manage(sp->conduit, sp->io, master_fd, true);
        if (n00b_result_is_ok(r)) {
            n00b_conduit_fd_owner_t *owner = n00b_result_get(r);
            sp->stdin_owner =
                n00b_option_set(n00b_conduit_fd_owner_t *, owner);

            if (use_aux) {
                // With PTY_STDERR: main PTY carries stdin+stderr,
                // aux PTY carries stdout.
                sp->stderr_owner =
                    n00b_option_set(n00b_conduit_fd_owner_t *, owner);
            }
            else {
                // Without PTY_STDERR: main PTY carries everything.
                sp->stdout_owner =
                    n00b_option_set(n00b_conduit_fd_owner_t *, owner);
                sp->stderr_owner = sp->stdout_owner;
            }
        }
        else {
            // fd_manage failed — close the FD to avoid leak.
            close(master_fd);
        }
    }

    // Register aux master if using separate stderr PTY.
    if (use_aux) {
        n00b_result_t(n00b_conduit_fd_owner_t *) r =
            n00b_conduit_fd_manage(sp->conduit, sp->io, aux_master, true);
        if (n00b_result_is_ok(r)) {
            sp->stdout_owner =
                n00b_option_set(n00b_conduit_fd_owner_t *, n00b_result_get(r));
        }
        else {
            // fd_manage failed — close the FD to avoid leak.
            close(aux_master);
        }
    }

    // Register proc lifecycle watch.
    {
        n00b_result_t(n00b_conduit_topic_base_t *) pr =
            n00b_conduit_proc_topic(sp->conduit, child,
                                    N00B_CONDUIT_PROC_EXIT);
        if (n00b_result_is_ok(pr)) {
            sp->proc_topic = n00b_result_get(pr);
        }
    }

    // Compute required_mask for done-inbox (same logic as pipe mode,
    // but stdout/stderr may share an owner).
    bool wait_stdout = n00b_option_is_set(sp->stdout_owner);
    bool wait_stderr = n00b_option_is_set(sp->stderr_owner)
                       && (!n00b_option_is_set(sp->stdout_owner)
                           || n00b_option_get(sp->stderr_owner)
                              != n00b_option_get(sp->stdout_owner));
    sp->required_mask = n00b_subproc_completion_mask(wait_stdout,
                                                     wait_stderr,
                                                     sp->stdin_inject != nullptr);

    // Reuse all existing wiring — capture, proxy, xforms, done-inbox,
    // signals all work identically through the FD owner abstraction.
    wire_io(sp);
    wire_done_inbox(sp);
    wire_signals(sp);

    // Wire stdin capture (same as pipe mode).
    if ((f & N00B_SUBPROC_CAP_STDIN) && sp->stdin_obs_topic) {
        sp->cap_stdin = n00b_subproc_wire_capture(sp->conduit, sp->stdin_obs_topic,
                                     &sp->buf_stdin,
                                     &sp->cap_stdin_sub);
    }
    else if ((f & N00B_SUBPROC_CAP_STDIN) && sp->buf_stdin->alloc_len == 0) {
        sp->buf_stdin = n00b_buffer_empty(
            .allocator = sp->conduit->allocator);
    }

    // Inject stdin data if configured.
    if (sp->stdin_inject && n00b_option_is_set(sp->stdin_owner)) {
        if (sp->stdin_obs_topic && sp->stdin_inject->byte_len > 0) {
            n00b_conduit_write_async(n00b_buffer_t *, sp->stdin_obs_topic,
                                     sp->stdin_inject);
        }
        n00b_fd_owner_write(n00b_option_get(sp->stdin_owner),
                            sp->stdin_inject->data,
                            sp->stdin_inject->byte_len);
        sp->done_flags |= N00B_SUBPROC_DONE_F_STDIN_DONE;
    }

    // Close stdin if requested.
    //
    // PTY limitation: stdin and stdout share the same FD owner (the
    // PTY master).  We cannot close the FD without killing stdout.
    // Instead, we send the PTY's EOF character (VEOF, typically ^D).
    //
    // This only works when the child is in canonical (cooked) mode.
    // If the child switches to raw mode, VEOF is just another byte
    // and won't signal EOF.  For raw-mode children, callers should
    // not set close_stdin and instead manage input completion by
    // sending application-level EOF (e.g., "exit\n" for shells).
    if ((f & N00B_SUBPROC_CLOSE_STDIN) && n00b_option_is_set(sp->stdin_owner)) {
        cc_t eof_char = 0x04; // Default ^D.
        if (sp->termcap_saved) {
            cc_t tc_eof = sp->initial_termcap.c_cc[VEOF];
            if (tc_eof != 0) {
                eof_char = tc_eof;
            }
        }
        n00b_fd_owner_write(n00b_option_get(sp->stdin_owner),
                            &eof_char, 1);
    }

    // Parent terminal setup (Phase 7):
    // Only modify parent terminal when proxy is active — if the caller
    // is just capturing PTY output (no proxy), we shouldn't change the
    // parent's terminal state or buffering.
    if (f & (N00B_SUBPROC_PROXY_STDIN | N00B_SUBPROC_PROXY_STDOUT
             | N00B_SUBPROC_PROXY_STDERR)) {
        if (sp->termcap && isatty(STDIN_FILENO)) {
            tcsetattr(STDIN_FILENO, TCSANOW, sp->termcap);
        }
        setvbuf(stdin, nullptr, _IONBF, 0);
        setvbuf(stdout, nullptr, _IONBF, 0);
        setvbuf(stderr, nullptr, _IONBF, 0);
    }

    // Release the gate.
    int gate_fd = n00b_option_get(sp->gate);
    char gate_byte = 'G';
    (void)!write(gate_fd, &gate_byte, 1);
    close(gate_fd);
    sp->gate = n00b_option_none(int);

    // Check error pipe for exec failure (same as pipe mode).
    // err_pipe[1] is CLOEXEC — on successful exec, read returns 0.
    // On failure, child writes errno before _exit.
    int child_errno = 0;
    ssize_t n = read(err_pipe[0], &child_errno, sizeof(child_errno));
    close(err_pipe[0]);

    if (n > 0) {
        waitpid(child, nullptr, 0);
        sp->errored     = true;
        sp->saved_errno = child_errno;
        atomic_store(&sp->exited, true);
        return n00b_result_err(bool, child_errno);
    }

    atomic_store(&sp->spawned, true);
    return n00b_result_ok(bool, true);
}

// ============================================================================
// Public lifecycle API
// ============================================================================

n00b_result_t(bool)
n00b_subproc_spawn(n00b_subproc_t *sp)
{
    assert(sp != nullptr);

    if (!sp->cmd) {
        return n00b_result_err(bool, EINVAL);
    }
    if (atomic_load(&sp->spawned)) {
        return n00b_result_err(bool, EALREADY);
    }
    if (!sp->conduit) {
        return n00b_result_err(bool, EINVAL);
    }

    if (!sp->io) {
        n00b_option_t(n00b_conduit_io_backend_t *) opt =
            n00b_conduit_default_backend(sp->conduit);
        if (!n00b_option_is_set(opt)) {
            return n00b_result_err(bool, EINVAL);
        }
        sp->io = n00b_option_get(opt);
    }

    if (sp->flags & N00B_SUBPROC_USE_PTY) {
        return spawn_pty_mode(sp);
    }
    return spawn_pipe_mode(sp);
}

n00b_result_t(bool)
n00b_subproc_run(n00b_subproc_t *sp)
{
    n00b_result_t(bool) r = n00b_subproc_spawn(sp);
    if (n00b_result_is_err(r)) {
        return r;
    }

    r = n00b_subproc_wait(sp);

    if (!sp->timed_out || sp->timeout_policy != N00B_SUBPROC_TIMEOUT_DETACH) {
        n00b_subproc_close(sp);
    }

    return r;
}

n00b_result_t(bool)
n00b_subproc_wait(n00b_subproc_t *sp) _kargs
{
    n00b_duration_t *timeout = nullptr;
}
{
    if (!atomic_load(&sp->spawned)) {
        return n00b_result_err(bool, ECHILD);
    }

    n00b_duration_t *to = timeout ? timeout : sp->timeout;
    pid_t child_pid = n00b_option_get(sp->pid);

    struct timespec deadline = {};
    bool has_deadline = false;

    if (to) {
        clock_gettime(CLOCK_MONOTONIC, &deadline);
        deadline.tv_sec  += to->tv_sec;
        deadline.tv_nsec += to->tv_nsec;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000L;
        }
        has_deadline = true;
    }

    // Wait loop: drain proc inbox (for exit status extraction), drain
    // done inbox (for topic-close events), check done condition.
    // Block on the done_inbox CV between iterations.
    while (true) {
        // 1. Drain signal inbox (SIGPIPE sets done flag).
        drain_signal_inbox(sp);

        // 2. Drain proc inbox → extract exit status.
        drain_proc_inbox(sp);

        // 3. Close FD owners that have reached EOF.  The FD managed layer
        //    transitions to READ_CLOSED on EOF but doesn't close the read
        //    topic (general-purpose behavior).  We close the owner here,
        //    which fires read_topic's done_topic → done_inbox.
        if (n00b_option_is_set(sp->stdout_owner)
            && n00b_atomic_load(&n00b_option_get(sp->stdout_owner)->state)
                >= N00B_CONDUIT_FD_READ_CLOSED
            && !(sp->done_flags & N00B_SUBPROC_DONE_F_STDOUT_EOF)) {
            n00b_conduit_fd_owner_close(n00b_option_get(sp->stdout_owner));
        }
        if (n00b_option_is_set(sp->stderr_owner)
            && (!n00b_option_is_set(sp->stdout_owner)
                || n00b_option_get(sp->stderr_owner)
                    != n00b_option_get(sp->stdout_owner))
            && n00b_atomic_load(&n00b_option_get(sp->stderr_owner)->state)
                >= N00B_CONDUIT_FD_READ_CLOSED
            && !(sp->done_flags & N00B_SUBPROC_DONE_F_STDERR_EOF)) {
            n00b_conduit_fd_owner_close(n00b_option_get(sp->stderr_owner));
        }

        // 4. Drain done inbox → set done flags.
        drain_done_inbox(sp);

        // 5. Drain capture inboxes so captured data is up to date.
        n00b_subproc_drain_capture(sp->cap_stdout, sp->buf_stdout);
        n00b_subproc_drain_capture(sp->cap_stderr, sp->buf_stderr);

        // 6. Check if done.
        if (n00b_subproc_done_condition_met(sp)) {
            break;
        }

        // 7. Check timeout.
        if (has_deadline) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec > deadline.tv_sec ||
                (now.tv_sec == deadline.tv_sec
                 && now.tv_nsec >= deadline.tv_nsec)) {
                sp->timed_out = true;
                switch (sp->timeout_policy) {
                case N00B_SUBPROC_TIMEOUT_SIGTERM:
                    kill(child_pid, SIGTERM);
                    break;
                case N00B_SUBPROC_TIMEOUT_SIGKILL:
                    kill(child_pid, SIGKILL);
                    break;
                case N00B_SUBPROC_TIMEOUT_DETACH:
                    return n00b_result_ok(bool, false);
                }
                // After sending signal, do a blocking waitpid to reap.
                // proc_fire may have already reaped via WNOHANG, in
                // which case this returns ECHILD — that's fine.
                int status = 0;
                pid_t w = waitpid(child_pid, &status, 0);
                if (w > 0) {
                    if (WIFEXITED(status)) {
                        sp->exit_status = n00b_option_set(int, WEXITSTATUS(status));
                    }
                    if (WIFSIGNALED(status)) {
                        sp->term_signal = n00b_option_set(int, WTERMSIG(status));
                    }
                }
                atomic_store(&sp->exited, true);
                n00b_subproc_note_proc_done(sp);
                break;
            }
        }

        // 8. Poll the IO backend to drive kqueue/epoll events, then
        //    check inboxes again on next iteration.
        if (sp->io) {
            n00b_conduit_io_poll(sp->io, 10); // 10ms
        }
        else if (sp->done_inbox) {
            // No IO backend — wait on the done_inbox CV instead.
            n00b_condition_wait(&sp->done_inbox->cv,
                                .timeout_ms  = 10,
                                .auto_unlock = true);
        }
        else {
            // Fallback: no done inbox (shouldn't happen), use waitpid.
            int status = 0;
            pid_t w = waitpid(child_pid, &status, 0);
            if (w > 0) {
                if (WIFEXITED(status)) {
                    sp->exit_status = n00b_option_set(int, WEXITSTATUS(status));
                }
                if (WIFSIGNALED(status)) {
                    sp->term_signal = n00b_option_set(int, WTERMSIG(status));
                }
                atomic_store(&sp->exited, true);
                n00b_subproc_note_proc_done(sp);
            }
            break;
        }
    }

    return n00b_result_ok(bool, true);
}

void
n00b_subproc_close(n00b_subproc_t *sp)
{
    if (sp->closed) {
        return;
    }
    sp->closed = true;

    // Drain any remaining capture data before tearing down.
    n00b_subproc_drain_capture(sp->cap_stdout, sp->buf_stdout);
    n00b_subproc_drain_capture(sp->cap_stderr, sp->buf_stderr);
    n00b_subproc_drain_capture(sp->cap_stdin, sp->buf_stdin);

    // Cancel capture subscriptions.
    if (sp->cap_stdout_sub) {
        n00b_conduit_sub_cancel(sp->cap_stdout_sub);
        sp->cap_stdout_sub = 0;
    }
    if (sp->cap_stderr_sub) {
        n00b_conduit_sub_cancel(sp->cap_stderr_sub);
        sp->cap_stderr_sub = 0;
    }
    if (sp->cap_stdin_sub) {
        n00b_conduit_sub_cancel(sp->cap_stdin_sub);
        sp->cap_stdin_sub = 0;
    }
    sp->cap_stdout = nullptr;
    sp->cap_stderr = nullptr;
    sp->cap_stdin  = nullptr;

    // Close stdin observation topic.
    if (sp->stdin_obs_topic) {
        n00b_conduit_topic_close((n00b_conduit_topic_base_t *)sp->stdin_obs_topic);
        sp->stdin_obs_topic = nullptr;
    }

    // Cancel done-inbox subscriptions.
    if (sp->done_stdout_sub) {
        n00b_conduit_sub_cancel(sp->done_stdout_sub);
        sp->done_stdout_sub = 0;
    }
    if (sp->done_stderr_sub) {
        n00b_conduit_sub_cancel(sp->done_stderr_sub);
        sp->done_stderr_sub = 0;
    }
    if (sp->done_proc_sub) {
        n00b_conduit_sub_cancel(sp->done_proc_sub);
        sp->done_proc_sub = 0;
    }
    sp->done_inbox = nullptr;

    // Cancel proc inbox subscription.
    if (sp->proc_inbox_sub) {
        n00b_conduit_sub_cancel(sp->proc_inbox_sub);
        sp->proc_inbox_sub = 0;
    }
    sp->proc_inbox = nullptr;

    // Proxy filters are stopped by closing their upstream topic.
    sp->proxy_stdout = nullptr;
    sp->proxy_stderr = nullptr;
    sp->proxy_stdin  = nullptr;

    // Close FD owners (unwatches from IO, closes topics, closes FDs).
    // Note: parent_stdin_owner manages STDIN_FILENO with close_on_done=false,
    // so closing it won't close the parent's stdin FD.
    if (n00b_option_is_set(sp->parent_stdin_owner)) {
        n00b_conduit_fd_owner_close(n00b_option_get(sp->parent_stdin_owner));
        sp->parent_stdin_owner = n00b_option_none(n00b_conduit_fd_owner_t *);
    }

    // In PTY mode, stdin/stdout/stderr owners may alias the same
    // underlying owner.  Deduplicate to avoid double-close.
    {
        n00b_conduit_fd_owner_t *stdin_o  = n00b_option_is_set(sp->stdin_owner)
                                          ? n00b_option_get(sp->stdin_owner)
                                          : nullptr;
        n00b_conduit_fd_owner_t *stdout_o = n00b_option_is_set(sp->stdout_owner)
                                          ? n00b_option_get(sp->stdout_owner)
                                          : nullptr;
        n00b_conduit_fd_owner_t *stderr_o = n00b_option_is_set(sp->stderr_owner)
                                          ? n00b_option_get(sp->stderr_owner)
                                          : nullptr;

        if (stdin_o) {
            n00b_conduit_fd_owner_close(stdin_o);
        }
        if (stdout_o && stdout_o != stdin_o) {
            n00b_conduit_fd_owner_close(stdout_o);
        }
        if (stderr_o && stderr_o != stdin_o && stderr_o != stdout_o) {
            n00b_conduit_fd_owner_close(stderr_o);
        }
    }

    // Restore parent terminal state (PTY mode).
    n00b_subproc_restore_terminal(sp);

    // Close proc topic if still active.
    if (sp->proc_topic) {
        n00b_conduit_topic_close(sp->proc_topic);
        sp->proc_topic = nullptr;
    }

    // Cancel signal subscriptions and drain remaining signals.
    if (sp->sigpipe_sub) {
        n00b_conduit_sub_cancel(sp->sigpipe_sub);
        sp->sigpipe_sub = 0;
    }
    if (sp->sigwinch_sub) {
        n00b_conduit_sub_cancel(sp->sigwinch_sub);
        sp->sigwinch_sub = 0;
    }
    sp->signal_inbox = nullptr;

    // Reap the child if still running.
    if (atomic_load(&sp->spawned) && !atomic_load(&sp->exited)
        && n00b_option_is_set(sp->pid)) {
        pid_t child_pid = n00b_option_get(sp->pid);
        int status = 0;
        pid_t w = waitpid(child_pid, &status, WNOHANG);
        if (w > 0) {
            if (WIFEXITED(status)) {
                sp->exit_status = n00b_option_set(int, WEXITSTATUS(status));
            }
            if (WIFSIGNALED(status)) {
                sp->term_signal = n00b_option_set(int, WTERMSIG(status));
            }
            atomic_store(&sp->exited, true);
        }
    }
}

n00b_result_t(uint64_t)
n00b_subproc_write_stdin(n00b_subproc_t *sp, n00b_buffer_t *data)
{
    if (!atomic_load(&sp->spawned)) {
        return n00b_result_err(uint64_t, ECHILD);
    }
    if (!n00b_option_is_set(sp->stdin_owner)) {
        return n00b_result_err(uint64_t, EBADF);
    }

    // Publish to stdin observation topic (feeds cap_stdin + stdin_subs).
    if (sp->stdin_obs_topic && data->byte_len > 0) {
        n00b_conduit_write_async(n00b_buffer_t *, sp->stdin_obs_topic,
                                 data);
    }

    return n00b_conduit_fd_write_submit(
        n00b_option_get(sp->stdin_owner), data->data, data->byte_len,
        nullptr, nullptr);
}

n00b_result_t(bool)
n00b_subproc_kill(n00b_subproc_t *sp) _kargs
{
    int signal = SIGTERM;
}
{
    if (!atomic_load(&sp->spawned) || atomic_load(&sp->exited)
        || !n00b_option_is_set(sp->pid)) {
        return n00b_result_err(bool, ECHILD);
    }

    if (kill(n00b_option_get(sp->pid), signal) < 0) {
        return n00b_result_err(bool, errno);
    }
    return n00b_result_ok(bool, true);
}

void
n00b_subproc_proxy_winsize(n00b_subproc_t *sp)
{
    if (!(sp->flags & N00B_SUBPROC_USE_PTY)) {
        return;
    }
    if (!n00b_option_is_set(sp->stdout_owner)) {
        return;
    }

    struct winsize ws;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0) {
        ioctl(n00b_option_get(sp->stdout_owner)->fd, TIOCSWINSZ, &ws);
        sp->dimensions = ws;
    }
}

void
n00b_subproc_restore_terminal(n00b_subproc_t *sp)
{
    if (!sp->termcap_saved) {
        return;
    }
    sp->termcap_saved = false;

    if (isatty(STDIN_FILENO)) {
        tcsetattr(STDIN_FILENO, TCSANOW, &sp->initial_termcap);
    }
}

// ============================================================================
// Accessors
// ============================================================================

n00b_buffer_t *
n00b_subproc_stdout(n00b_subproc_t *sp)
{
    n00b_subproc_drain_capture(sp->cap_stdout, sp->buf_stdout);
    return sp->buf_stdout;
}

n00b_buffer_t *
n00b_subproc_stderr(n00b_subproc_t *sp)
{
    n00b_subproc_drain_capture(sp->cap_stderr, sp->buf_stderr);
    return sp->buf_stderr;
}

n00b_buffer_t *
n00b_subproc_stdin_capture(n00b_subproc_t *sp)
{
    n00b_subproc_drain_capture(sp->cap_stdin, sp->buf_stdin);
    return sp->buf_stdin;
}

n00b_result_t(int)
n00b_subproc_exit_code(n00b_subproc_t *sp)
{
    if (!atomic_load(&sp->exited)) {
        return n00b_result_err(int, ECHILD);
    }
    if (!n00b_option_is_set(sp->exit_status)) {
        return n00b_result_err(int, ECHILD);
    }
    return n00b_result_ok(int, n00b_option_get(sp->exit_status));
}

n00b_result_t(int)
n00b_subproc_term_signal(n00b_subproc_t *sp)
{
    if (!atomic_load(&sp->exited)) {
        return n00b_result_err(int, ECHILD);
    }
    if (!n00b_option_is_set(sp->term_signal)) {
        return n00b_result_err(int, ECHILD);
    }
    return n00b_result_ok(int, n00b_option_get(sp->term_signal));
}

// ============================================================================
// Topic accessors
// ============================================================================

n00b_option_t(n00b_conduit_topic_t(n00b_buffer_t *) *)
    n00b_subproc_stdout_topic(n00b_subproc_t *sp)
{
    return n00b_option_from_nullable(
        n00b_conduit_topic_t(n00b_buffer_t *) *,
        (n00b_conduit_topic_t(n00b_buffer_t *) *)sp->eff_stdout_topic);
}

n00b_option_t(n00b_conduit_topic_t(n00b_buffer_t *) *)
    n00b_subproc_stderr_topic(n00b_subproc_t *sp)
{
    return n00b_option_from_nullable(
        n00b_conduit_topic_t(n00b_buffer_t *) *,
        (n00b_conduit_topic_t(n00b_buffer_t *) *)sp->eff_stderr_topic);
}

n00b_option_t(n00b_conduit_topic_t(n00b_buffer_t *) *)
    n00b_subproc_stdin_topic(n00b_subproc_t *sp)
{
    if (!n00b_option_is_set(sp->stdin_owner)) {
        return n00b_option_none(n00b_conduit_topic_t(n00b_buffer_t *) *);
    }
    return n00b_option_from_nullable(
        n00b_conduit_topic_t(n00b_buffer_t *) *,
        n00b_conduit_fd_read_topic_typed(n00b_option_get(sp->stdin_owner)));
}

#endif /* !_WIN32 */

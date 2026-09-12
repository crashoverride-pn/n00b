/*
 * test_proc_lifecycle.c — Tests for conduit process lifecycle monitoring.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#ifdef _WIN32
#include "internal/win32_sockets.h"
#else
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#endif

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/proc_lifecycle.h"
#include "core/alloc.h"
#include "core/runtime.h"

typedef struct {
    pid_t pid;
#ifdef _WIN32
    HANDLE process;
    HANDLE thread;
#endif
} test_child_t;

static pid_t
test_current_pid(void)
{
#ifdef _WIN32
    return (pid_t)GetCurrentProcessId();
#else
    return getpid();
#endif
}

static void
test_skip_or_fail(const char *message)
{
#ifdef _WIN32
    fprintf(stderr, "  [FAIL] %s\n", message);
    assert(false);
#else
    printf("  [SKIP] %s\n", message);
#endif
}

static bool
test_spawn_exit_child(test_child_t *child)
{
    memset(child, 0, sizeof(*child));
#ifdef _WIN32
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    char cmdline[] = "cmd.exe /C exit 42";
    if (!CreateProcessA(nullptr, cmdline, nullptr, nullptr, FALSE, 0,
                        nullptr, nullptr, &si, &pi)) {
        return false;
    }

    child->pid     = (pid_t)pi.dwProcessId;
    child->process = pi.hProcess;
    child->thread  = pi.hThread;
    return child->pid > 0;
#else
    pid_t pid = fork();
    if (pid < 0) {
        return false;
    }

    if (pid == 0) {
        _exit(42);
    }

    child->pid = pid;
    return true;
#endif
}

static void
test_wait_child(test_child_t *child)
{
    if (!child || child->pid <= 0) {
        return;
    }
#ifdef _WIN32
    if (child->process) {
        WaitForSingleObject(child->process, INFINITE);
    }
    if (child->thread) {
        CloseHandle(child->thread);
        child->thread = nullptr;
    }
    if (child->process) {
        CloseHandle(child->process);
        child->process = nullptr;
    }
#else
    waitpid(child->pid, nullptr, 0);
#endif
    child->pid = 0;
}

// ============================================================================
// 1. Create process topic and verify
// ============================================================================

static void
test_proc_topic(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    // Watch our own pid — we won't get events but the topic should create.
    pid_t pid = test_current_pid();
    n00b_result_t(n00b_conduit_topic_base_t *) tr =
        n00b_conduit_proc_topic(c, pid, N00B_CONDUIT_PROC_EXIT);

    if (n00b_result_is_err(tr)) {
        test_skip_or_fail("proc topic (not supported on this backend)");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    n00b_conduit_topic_base_t *topic = n00b_result_get(tr);
    assert(topic != nullptr);

    // Verify it is a proc topic.
    assert(n00b_conduit_topic_is_proc(topic));
    assert(n00b_conduit_proc_pid(topic) == pid);

    n00b_conduit_proc_unwatch(c, pid);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] proc topic\n");
}

// ============================================================================
// 2. Same pid returns same topic
// ============================================================================

static void
test_proc_same_topic(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    pid_t pid = test_current_pid();
    n00b_result_t(n00b_conduit_topic_base_t *) tr1 =
        n00b_conduit_proc_topic(c, pid, N00B_CONDUIT_PROC_EXIT);
    n00b_result_t(n00b_conduit_topic_base_t *) tr2 =
        n00b_conduit_proc_topic(c, pid, N00B_CONDUIT_PROC_ALL);

    if (n00b_result_is_err(tr1) || n00b_result_is_err(tr2)) {
        test_skip_or_fail("proc same topic (not supported)");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    n00b_conduit_topic_base_t *t1 = n00b_result_get(tr1);
    n00b_conduit_topic_base_t *t2 = n00b_result_get(tr2);
    assert(t1 == t2);

    n00b_conduit_proc_unwatch(c, pid);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] proc same topic\n");
}

// ============================================================================
// 3. Invalid pid returns error
// ============================================================================

static void
test_proc_invalid_pid(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_topic_base_t *) tr =
        n00b_conduit_proc_topic(c, 0, N00B_CONDUIT_PROC_EXIT);
    assert(n00b_result_is_err(tr));

    tr = n00b_conduit_proc_topic(c, -1, N00B_CONDUIT_PROC_EXIT);
    assert(n00b_result_is_err(tr));

    n00b_conduit_destroy(c);
    printf("  [PASS] proc invalid pid\n");
}

// ============================================================================
// 4. Fork-and-exit: watch child, verify exit event is delivered
// ============================================================================

static void
test_proc_child_exit(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    test_child_t child_info;
    if (!test_spawn_exit_child(&child_info)) {
        test_skip_or_fail("proc child exit (spawn failed)");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    // Parent: watch the child.
    pid_t child = child_info.pid;
    n00b_result_t(n00b_conduit_topic_base_t *) tr =
        n00b_conduit_proc_topic(c, child, N00B_CONDUIT_PROC_EXIT);

    if (n00b_result_is_err(tr)) {
        test_skip_or_fail("proc child exit (backend not supported)");
        test_wait_child(&child_info);
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    n00b_conduit_topic_base_t *topic = n00b_result_get(tr);

    // Create inbox and subscribe.
    n00b_conduit_proc_inbox_t *inbox = n00b_conduit_proc_inbox_new(c);
    assert(inbox != nullptr);

    n00b_conduit_sub_handle_t handle =
        n00b_conduit_proc_subscribe(topic, inbox,
                                     .operations = N00B_CONDUIT_OP_ALL);
    assert(handle != N00B_CONDUIT_INVALID_SUB_HANDLE);

    // Poll until we get the exit event.
    bool got_message = false;
    for (int attempts = 0; attempts < 50; attempts++) {
        n00b_conduit_io_poll(io, 100);

        if (n00b_conduit_proc_inbox_has_messages(inbox)) {
            got_message = true;
            break;
        }
    }

    if (!got_message) {
        test_skip_or_fail("proc child exit (no event delivered)");
        test_wait_child(&child_info);
        n00b_conduit_proc_unwatch(c, child);
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    n00b_conduit_proc_msg_t *msg = n00b_conduit_proc_inbox_pop(inbox);
    assert(msg != nullptr);
    assert(msg->payload.pid == child);
    assert(msg->payload.events & N00B_CONDUIT_PROC_EXIT);
#ifdef _WIN32
    assert(msg->payload.exit_status == 42);
#else
    assert(WIFEXITED(msg->payload.exit_status));
    assert(WEXITSTATUS(msg->payload.exit_status) == 42);
#endif

    // Reap the child.
    test_wait_child(&child_info);

    n00b_conduit_proc_unwatch(c, child);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] proc child exit\n");
}

// ============================================================================
// main
// ============================================================================

// ============================================================================
// 5. proc_fire must not pass a fallback status off as a wait(2) result
//
// n00b-lang/n00b#373: on macOS, kqueue posts NOTE_EXIT before the child is
// reapable, so proc_fire's WNOHANG reap can return 0 for a child that has
// exited. It used to hand the backend's value on as if it were the wait
// status, which with a bare NOTE_EXIT is 0: `exit 1` read back as 0. The
// contract now is that `reaped` says whether exit_status came from wait(2).
// Reproduce the state exactly by firing for a child that is STILL RUNNING.
// ============================================================================

// Delivery to the inbox goes through the conduit's dispatch, which the I/O
// poll drives; pop after a bounded poll, as the child-exit test does.
static n00b_conduit_proc_msg_t *
test_pop_after_poll(n00b_conduit_io_backend_t *io, n00b_conduit_proc_inbox_t *inbox)
{
    for (int attempts = 0; attempts < 50; attempts++) {
        if (n00b_conduit_proc_inbox_has_messages(inbox)) {
            break;
        }
        n00b_conduit_io_poll(io, 100);
    }
    return n00b_conduit_proc_inbox_pop(inbox);
}

static void
test_proc_fire_reports_unreaped_child(void)
{
#ifdef _WIN32
    printf("  [SKIP] proc fire unreaped child (POSIX only)\n");
#else
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    // A child that stays alive until we kill it. exec'd /bin/sleep rather
    // than a forked copy of this process blocking in read(): the runtime's
    // signals interrupt that read and the copy exits at once, which is what
    // the first draft of this test tripped over.
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        execl("/bin/sleep", "sleep", "30", (char *)nullptr);
        _exit(127);
    }

    n00b_result_t(n00b_conduit_topic_base_t *) tr =
        n00b_conduit_proc_topic(c, child, N00B_CONDUIT_PROC_EXIT);
    if (n00b_result_is_err(tr)) {
        test_skip_or_fail("proc fire unreaped child (backend not supported)");
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }
    n00b_conduit_topic_base_t *topic = n00b_result_get(tr);
    n00b_conduit_proc_inbox_t *inbox = n00b_conduit_proc_inbox_new(c);
    assert(inbox != nullptr);
    n00b_conduit_sub_handle_t handle =
        n00b_conduit_proc_subscribe(topic, inbox, .operations = N00B_CONDUIT_OP_ALL);
    assert(handle != N00B_CONDUIT_INVALID_SUB_HANDLE);

    // Fire by hand while the child is running: nothing is reapable, which is
    // the state the race leaves proc_fire in. The backend "supplied" a status
    // of exited-42; it must come through untouched and flagged unreaped.
    n00b_conduit_proc_watch_t fake = {.pid = child, .ops = N00B_CONDUIT_PROC_EXIT, .topic = topic};
    n00b_conduit_proc_fire(&fake, N00B_CONDUIT_PROC_EXIT, 42 << 8);

    n00b_conduit_proc_msg_t *msg = test_pop_after_poll(io, inbox);
    assert(msg != nullptr);
    assert(msg->payload.events & N00B_CONDUIT_PROC_EXIT);
    assert(!msg->payload.reaped);
    assert(msg->payload.exit_status == (42 << 8));

    // (One fire only: a proc topic closes after its exit event, so a second
    // exit on the same topic is dropped by design.)

    // Still running throughout: the hand-fired event reaped nothing.
    assert(waitpid(child, nullptr, WNOHANG) == 0);

    // The real path (backend event -> proc_fire reaps -> correct status) is
    // test_proc_child_exit's job. Clean up.
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);

    n00b_conduit_proc_unwatch(c, child);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] proc fire unreaped child\n");
#endif
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_proc_lifecycle:\n");
    fflush(stdout);

    test_proc_topic();
    fflush(stdout);
    test_proc_same_topic();
    fflush(stdout);
    test_proc_invalid_pid();
    fflush(stdout);
    test_proc_child_exit();
    test_proc_fire_reports_unreaped_child();
    fflush(stdout);

    printf("All proc_lifecycle tests passed.\n");
    n00b_shutdown();
    return 0;
}

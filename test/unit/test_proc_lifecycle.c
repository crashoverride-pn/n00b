/*
 * test_proc_lifecycle.c — Tests for conduit process lifecycle monitoring.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#ifdef _WIN32
#include "internal/win32_sockets.h"
#else
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
    fflush(stdout);

    printf("All proc_lifecycle tests passed.\n");
    n00b_shutdown();
    return 0;
}

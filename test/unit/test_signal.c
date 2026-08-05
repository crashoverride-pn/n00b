/*
 * test_signal.c — Tests for conduit signal topics.
 */

#include <stdio.h>
#include <assert.h>
#include <signal.h>
#ifdef __linux__
#include <pthread.h>
#endif
#ifndef _WIN32
#include <unistd.h>
#endif

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/signal.h"
#include "core/alloc.h"
#include "core/runtime.h"

#ifdef _WIN32
#define N00B_TEST_SIGNAL_ONE SIGINT
#define N00B_TEST_SIGNAL_TWO SIGTERM
#else
#define N00B_TEST_SIGNAL_ONE SIGUSR1
#define N00B_TEST_SIGNAL_TWO SIGUSR2
#endif

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

// ============================================================================
// 1. Create signal topic and verify
// ============================================================================

static void
test_signal_topic(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    n00b_result_t(n00b_conduit_topic_base_t *) tr =
        n00b_conduit_signal_topic(c, N00B_TEST_SIGNAL_ONE);

    if (n00b_result_is_err(tr)) {
        test_skip_or_fail("signal topic (not supported)");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    n00b_conduit_topic_base_t *topic = n00b_result_get(tr);
    assert(topic != nullptr);

    // Verify it is a signal topic.
    assert(n00b_conduit_topic_is_signal(topic));
    assert(n00b_conduit_signal_num(topic) == N00B_TEST_SIGNAL_ONE);

    n00b_conduit_signal_unwatch(c, N00B_TEST_SIGNAL_ONE);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] signal topic\n");
}

// ============================================================================
// 2. Same signal returns same topic
// ============================================================================

static void
test_signal_same_topic(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    n00b_result_t(n00b_conduit_topic_base_t *) tr1 =
        n00b_conduit_signal_topic(c, N00B_TEST_SIGNAL_TWO);
    n00b_result_t(n00b_conduit_topic_base_t *) tr2 =
        n00b_conduit_signal_topic(c, N00B_TEST_SIGNAL_TWO);

    if (n00b_result_is_err(tr1) || n00b_result_is_err(tr2)) {
        test_skip_or_fail("signal same topic (not supported)");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    n00b_conduit_topic_base_t *t1 = n00b_result_get(tr1);
    n00b_conduit_topic_base_t *t2 = n00b_result_get(tr2);
    assert(t1 == t2);

    n00b_conduit_signal_unwatch(c, N00B_TEST_SIGNAL_TWO);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] signal same topic\n");
}

// ============================================================================
// 3. Raised signal delivers a topic message
// ============================================================================

static void
test_signal_delivery(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    n00b_result_t(n00b_conduit_topic_base_t *) tr =
        n00b_conduit_signal_topic(c, N00B_TEST_SIGNAL_ONE);

    if (n00b_result_is_err(tr)) {
        test_skip_or_fail("signal delivery (not supported)");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }

    n00b_conduit_topic_base_t *topic = n00b_result_get(tr);
    n00b_conduit_signal_inbox_t *inbox = n00b_conduit_signal_inbox_new(c);
    assert(inbox != nullptr);

    n00b_conduit_sub_handle_t handle =
        n00b_conduit_signal_subscribe(topic, inbox,
                                      .operations = N00B_CONDUIT_OP_ALL);
    assert(handle != N00B_CONDUIT_INVALID_SUB_HANDLE);

    // Linux epoll/io_uring backends use signalfd, which receives only
    // signals blocked on the polling thread.  Send the test signal to this
    // thread so another runtime thread cannot take the default SIGUSR1 action.
    // Non-Linux backends keep process-directed delivery for kqueue/poll.
#ifdef __linux__
    assert(pthread_kill(pthread_self(), N00B_TEST_SIGNAL_ONE) == 0);
#elif defined(_WIN32)
    raise(N00B_TEST_SIGNAL_ONE);
#else
    kill(getpid(), N00B_TEST_SIGNAL_ONE);
#endif

    bool got_message = false;
    for (int attempts = 0; attempts < 50; attempts++) {
        n00b_conduit_io_poll(io, 100);
        if (n00b_conduit_signal_inbox_has_messages(inbox)) {
            got_message = true;
            break;
        }
    }

    assert(got_message);

    n00b_conduit_signal_msg_t *msg = n00b_conduit_signal_inbox_pop(inbox);
    assert(msg != nullptr);
    assert(msg->payload.signum == N00B_TEST_SIGNAL_ONE);
    assert(msg->payload.raise_count >= 1);

    n00b_conduit_signal_unwatch(c, N00B_TEST_SIGNAL_ONE);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] signal delivery\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_signal:\n");
    fflush(stdout);

    test_signal_topic();
    fflush(stdout);
    test_signal_same_topic();
    fflush(stdout);
    test_signal_delivery();
    fflush(stdout);

    printf("All signal tests passed.\n");
    n00b_shutdown();
    return 0;
}

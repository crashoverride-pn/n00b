/*
 * test_fd_managed.c — Tests for managed FD lifecycle.
 *
 * Tests use pipe pairs to exercise the managed FD owner registration,
 * lookup, and topic accessors.
 */

#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
#include <string.h>
#ifndef _WIN32
#include <spawn.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#endif

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/fd_managed.h"
#include "core/alloc.h"
#include "core/pool.h"
#include "core/runtime.h"

// ============================================================================
// 1. Manage and lookup FD owner
// ============================================================================

static int
test_pipe_create(int fds[2])
{
#ifdef _WIN32
    return _pipe(fds, 4096, _O_BINARY);
#else
    return pipe(fds);
#endif
}

static int
test_fd_close(int fd)
{
#ifdef _WIN32
    return _close(fd);
#else
    return close(fd);
#endif
}

static void
test_fd_manage_lookup(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    int fds[2];
    int rc = test_pipe_create(fds);
    assert(rc == 0);

    // Manage the read end (do NOT auto-close — we close manually).
    auto manage_r = n00b_conduit_fd_manage(c, io, fds[0], false);
    assert(n00b_result_is_ok(manage_r));
    n00b_conduit_fd_owner_t *owner = n00b_result_get(manage_r);
    assert(owner->fd == (base_socket_t)fds[0]);

    // Lookup should return the same owner.
    auto found_opt = n00b_conduit_fd_get_owner(c, fds[0]);
    assert(n00b_option_is_set(found_opt));
    assert(n00b_option_get(found_opt) == owner);

    // Lookup for unmanaged FD returns None.
    auto missing_opt = n00b_conduit_fd_get_owner(c, fds[1]);
    assert(!n00b_option_is_set(missing_opt));

    test_fd_close(fds[0]);
    test_fd_close(fds[1]);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] FD manage/lookup\n");
}

// ============================================================================
// 2. Owner exposes read/write/status topics
// ============================================================================

static void
test_fd_owner_topics(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    int fds[2];
    int rc = test_pipe_create(fds);
    assert(rc == 0);

    auto manage_r = n00b_conduit_fd_manage(c, io, fds[0], false);
    assert(n00b_result_is_ok(manage_r));
    n00b_conduit_fd_owner_t *owner = n00b_result_get(manage_r);

    // Topic accessors should succeed.
    n00b_conduit_topic_base_t *rt = n00b_result_get(n00b_conduit_fd_read_topic(owner));
    n00b_conduit_topic_base_t *wt = n00b_result_get(n00b_conduit_fd_write_topic(owner));
    n00b_conduit_topic_base_t *st = n00b_result_get(n00b_conduit_fd_status_topic(owner));

    // They should all be distinct topics.
    assert(rt != wt);
    assert(rt != st);
    assert(wt != st);

    n00b_conduit_topic_t(n00b_buffer_t *) *read_typed =
        n00b_conduit_fd_read_topic_typed(owner);
    assert(read_typed != nullptr);
    assert(n00b_list_len(read_typed->subscriptions) == 0);

    n00b_conduit_topic_t(n00b_conduit_fd_write_payload_t) *write_typed =
        n00b_conduit_fd_write_topic_typed(owner);
    assert(write_typed != nullptr);
    assert(n00b_list_len(write_typed->subscriptions) == 0);

    n00b_conduit_topic_t(n00b_conduit_fd_status_payload_t) *status_typed =
        n00b_conduit_fd_status_topic_typed(owner);
    assert(status_typed != nullptr);
    assert(n00b_list_len(status_typed->subscriptions) == 0);

    n00b_conduit_inbox_t(n00b_buffer_t *) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(n00b_buffer_t *));
    n00b_conduit_inbox_init(n00b_buffer_t *, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_sub_handle_t h =
        n00b_conduit_subscribe(n00b_buffer_t *, read_typed, inbox);
    assert(h != N00B_CONDUIT_INVALID_SUB_HANDLE);
    assert(n00b_list_len(read_typed->subscriptions) == 1);
    n00b_conduit_sub_cancel(h);

    test_fd_close(fds[0]);
    test_fd_close(fds[1]);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] FD owner topics\n");
}

// ============================================================================
// 3. Writes without observers do not retain write-observation payloads
// ============================================================================

static void
test_fd_write_no_observer_no_payload_retention(void)
{
#ifdef _WIN32
    return;
#else
    n00b_runtime_t *rt = n00b_get_runtime();
    assert(rt != nullptr);

    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    int fd = open("/dev/null", O_WRONLY);
    assert(fd >= 0);

    auto manage_r = n00b_conduit_fd_manage(c, io, fd, true);
    assert(n00b_result_is_ok(manage_r));
    n00b_conduit_fd_owner_t *owner = n00b_result_get(manage_r);

    char payload[2048];
    memset(payload, 0x5a, sizeof(payload));

    uint64_t before =
        n00b_pool_mapped_bytes(&rt->system_pool);

    for (int i = 0; i < 1024; i++) {
        auto write_r = n00b_fd_owner_write_attempt(owner,
                                                   payload,
                                                   sizeof(payload));
        assert(n00b_result_is_ok(write_r));
        n00b_fd_owner_write_attempt_t attempt = n00b_result_get(write_r);
        assert(!attempt.error);
        assert(attempt.bytes_written == sizeof(payload));
    }

    uint64_t after =
        n00b_pool_mapped_bytes(&rt->system_pool);
    assert(after >= before);
    assert(after - before < 512 * 1024);

    auto close_r = n00b_conduit_fd_owner_close_result(owner);
    assert(n00b_result_is_ok(close_r));

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] FD write without observers retains no payload copies\n");
#endif
}

// ============================================================================
// 4. Stream EOF before data
// ============================================================================

static bool
test_stream_push(void *inbox, void *msg)
{
    return n00b_conduit_inbox_push_msg(
        n00b_conduit_fd_stream_payload_t,
        (n00b_conduit_fd_stream_inbox_t *)inbox,
        (n00b_conduit_fd_stream_msg_t *)msg);
}

static void
test_fd_stream_empty_eof(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    int fds[2];
    int rc = test_pipe_create(fds);
    assert(rc == 0);

    test_fd_close(fds[1]);

    auto manage_r = n00b_conduit_fd_manage(c, io, fds[0], true);
    assert(n00b_result_is_ok(manage_r));
    n00b_conduit_fd_owner_t *owner = n00b_result_get(manage_r);

    auto reader_r = n00b_conduit_stream_reader_new(c, owner);
    assert(n00b_result_is_ok(reader_r));
    n00b_conduit_stream_reader_t *reader = n00b_result_get(reader_r);

    n00b_conduit_fd_stream_inbox_t *inbox =
        n00b_conduit_fd_stream_inbox_new(c);

    n00b_conduit_stream_read_until(reader,
                                   '\n',
                                   1024,
                                   inbox,
                                   test_stream_push);

    n00b_conduit_fd_stream_msg_t *msg = nullptr;
    for (int i = 0; i < 20 && msg == nullptr; i++) {
        (void)n00b_conduit_io_poll(io, 50);
        n00b_conduit_stream_reader_process(reader);
        msg = n00b_conduit_fd_stream_inbox_pop(inbox);
    }

    assert(msg != nullptr);
    assert(msg->payload.len == 0);
    assert(msg->payload.eof);
    assert(!msg->payload.error);

    n00b_conduit_stream_reader_destroy(reader);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] stream empty EOF\n");
}

#ifndef _WIN32
// ============================================================================
// 5. A hung-up fd with no read or write interest does not wake the backend
// ============================================================================

static int
test_poll_event_count(n00b_conduit_io_backend_t *io, int rounds)
{
    int total = 0;
    for (int i = 0; i < rounds; i++) {
        auto poll_r = n00b_conduit_io_poll(io, 20);
        assert(n00b_result_is_ok(poll_r));
        total += n00b_result_get(poll_r);
    }
    return total;
}

static void
test_fd_hup_without_interest_on(const n00b_conduit_io_ops_t *ops,
                                const char                  *label)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new(c, ops);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    // The read end of a pipe whose writer is gone, which is what fd 0 is
    // under `true | prog` or a non-interactive ssh session.
    int fds[2];
    int rc = test_pipe_create(fds);
    assert(rc == 0);
    test_fd_close(fds[1]);

    auto manage_r = n00b_conduit_fd_manage(c, io, fds[0], true);
    assert(n00b_result_is_ok(manage_r));
    n00b_conduit_fd_owner_t *owner = n00b_result_get(manage_r);

    // Managed but unsubscribed: the hangup must not surface as an event.
    int idle_events = test_poll_event_count(io, 5);
    if (idle_events != 0) {
        fprintf(stderr, "  %s: %d events for an fd nobody reads\n",
                label, idle_events);
    }
    assert(idle_events == 0);

    // A reader gets EOF, and after that the fd goes quiet again.
    auto reader_r = n00b_conduit_stream_reader_new(c, owner);
    assert(n00b_result_is_ok(reader_r));
    n00b_conduit_stream_reader_t *reader = n00b_result_get(reader_r);

    n00b_conduit_fd_stream_inbox_t *inbox =
        n00b_conduit_fd_stream_inbox_new(c);
    n00b_conduit_stream_read_until(reader, '\n', 1024, inbox, test_stream_push);

    n00b_conduit_fd_stream_msg_t *msg = nullptr;
    for (int i = 0; i < 20 && msg == nullptr; i++) {
        (void)n00b_conduit_io_poll(io, 50);
        n00b_conduit_stream_reader_process(reader);
        msg = n00b_conduit_fd_stream_inbox_pop(inbox);
    }
    assert(msg != nullptr);
    assert(msg->payload.eof);

    int after_eof_events = test_poll_event_count(io, 5);
    if (after_eof_events != 0) {
        fprintf(stderr, "  %s: %d events after EOF was delivered\n",
                label, after_eof_events);
    }
    assert(after_eof_events == 0);

    n00b_conduit_stream_reader_destroy(reader);
    n00b_conduit_fd_owner_close(owner);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] hung-up fd without interest is quiet (%s)\n", label);
}

static void
test_fd_hup_without_interest(void)
{
    auto default_r = n00b_conduit_io_default_ops();
    assert(n00b_result_is_ok(default_r));
    test_fd_hup_without_interest_on(n00b_result_get(default_r), "default");

    auto poll_r = n00b_conduit_io_poll_ops();
    assert(n00b_result_is_ok(poll_r));
    test_fd_hup_without_interest_on(n00b_result_get(poll_r), "poll");
}

// ============================================================================
// 6. A runtime whose stdin is a hung-up pipe idles without spinning
// ============================================================================

#define IDLE_CHILD_FLAG  "--idle-with-hung-up-stdin"
#define IDLE_WINDOW_MS   1000

extern char **environ;

static int64_t
test_process_cpu_us(void)
{
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    return (int64_t)(ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) * 1000000
         + ru.ru_utime.tv_usec + ru.ru_stime.tv_usec;
}

// Runs in the spawned child after n00b_init has registered fd 0 with the
// default IO thread. Prints the CPU the whole process burned while the main
// thread slept, which is what a spinning IO thread shows up as.
static int
idle_child_main(void)
{
    int64_t         before = test_process_cpu_us();
    struct timespec ts     = {
            .tv_sec  = IDLE_WINDOW_MS / 1000,
            .tv_nsec = (long)(IDLE_WINDOW_MS % 1000) * 1000000L,
    };
    while (nanosleep(&ts, &ts) != 0) {
    }
    printf("%lld\n", (long long)(test_process_cpu_us() - before));
    fflush(stdout);
    return 0;
}

static void
test_cloexec(int fd)
{
    fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
}

static void
test_runtime_idle_with_hung_up_stdin(char *self)
{
    int in[2];
    int out[2];
    assert(pipe(in) == 0);
    assert(pipe(out) == 0);
    test_cloexec(in[0]);
    test_cloexec(in[1]);
    test_cloexec(out[0]);
    test_cloexec(out[1]);

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, in[0], 0);
    posix_spawn_file_actions_adddup2(&fa, out[1], 1);

    char *child_argv[] = {self, IDLE_CHILD_FLAG, nullptr};
    pid_t pid          = 0;
    int   rc = posix_spawn(&pid, self, &fa, nullptr, child_argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    assert(rc == 0);

    // Every write end of the child's stdin is now closed.
    close(in[0]);
    close(in[1]);
    close(out[1]);

    char    buf[64] = {0};
    size_t  used    = 0;
    ssize_t n;
    while (used < sizeof(buf) - 1
           && (n = read(out[0], buf + used, sizeof(buf) - 1 - used)) != 0) {
        if (n > 0) {
            used += (size_t)n;
        }
    }
    close(out[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
    }
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    long long cpu_us = strtoll(buf, nullptr, 10);
    long long limit  = (long long)IDLE_WINDOW_MS * 1000 / 4;
    if (cpu_us >= limit) {
        fprintf(stderr,
                "  child burned %lld us of CPU in a %d ms idle window\n",
                cpu_us, IDLE_WINDOW_MS);
    }
    assert(used > 0);
    assert(cpu_us < limit);
    printf("  [PASS] runtime idles with hung-up stdin (%lld us CPU in %d ms)\n",
           cpu_us, IDLE_WINDOW_MS);
}
#endif

// ============================================================================
// 7. Null args
// ============================================================================

static void
test_fd_null_args(void)
{
    // Null conduit or IO should return error.
    auto manage_r = n00b_conduit_fd_manage(nullptr, nullptr, 0, false);
    assert(n00b_result_is_err(manage_r));

    // Null topic accessors should return Err.
    assert(n00b_result_is_err(n00b_conduit_fd_read_topic(nullptr)));
    assert(n00b_result_is_err(n00b_conduit_fd_write_topic(nullptr)));
    assert(n00b_result_is_err(n00b_conduit_fd_status_topic(nullptr)));

    printf("  [PASS] null args\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

#ifndef _WIN32
    if (argc > 1 && strcmp(argv[1], IDLE_CHILD_FLAG) == 0) {
        int child_rc = idle_child_main();
        n00b_shutdown();
        return child_rc;
    }
#endif

    printf("test_fd_managed:\n");
    fflush(stdout);

    test_fd_manage_lookup();
    fflush(stdout);
    test_fd_owner_topics();
    fflush(stdout);
    test_fd_write_no_observer_no_payload_retention();
    fflush(stdout);
    test_fd_stream_empty_eof();
    fflush(stdout);
#ifndef _WIN32
    test_fd_hup_without_interest();
    fflush(stdout);
    test_runtime_idle_with_hung_up_stdin(argv[0]);
    fflush(stdout);
#endif
    test_fd_null_args();
    fflush(stdout);

    printf("All fd_managed tests passed.\n");
    n00b_shutdown();
    return 0;
}

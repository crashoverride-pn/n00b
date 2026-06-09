/*
 * test_fd_managed.c — Tests for managed FD lifecycle.
 *
 * Tests use pipe pairs to exercise the managed FD owner registration,
 * lookup, and topic accessors.
 */

#include <stdio.h>
#include <assert.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <unistd.h>
#endif
#include <string.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/fd_managed.h"
#include "core/alloc.h"
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
    assert(owner->fd == fds[0]);

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
// 3. Stream EOF before data
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

// ============================================================================
// 4. Null args
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

    printf("test_fd_managed:\n");
    fflush(stdout);

    test_fd_manage_lookup();
    fflush(stdout);
    test_fd_owner_topics();
    fflush(stdout);
    test_fd_stream_empty_eof();
    fflush(stdout);
    test_fd_null_args();
    fflush(stdout);

    printf("All fd_managed tests passed.\n");
    n00b_shutdown();
    return 0;
}

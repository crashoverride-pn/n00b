/*
 * test_fd_owner_read_all.c -- Regression test for `n00b_fd_owner_read_all`.
 *
 * Verifies the blocking bulk-read helper that mirrors
 * `n00b_fd_owner_write` on the read side. The helper subscribes to the
 * owner's read topic, accumulates every published `n00b_buffer_t *`
 * chunk into a freshly-allocated buffer, and returns once the IO
 * thread signals end-of-stream (TOPIC_CLOSED on the read inbox sys
 * queue or an empty-payload chunk).
 *
 * The test wires up a pipe through the runtime's default conduit,
 * writes a known payload to the write side from the test thread,
 * closes the write side to trigger EOF, then drains the read side
 * with `n00b_fd_owner_read_all` and checks that the returned buffer
 * matches the payload byte-for-byte.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <unistd.h>
#endif

#include "n00b.h"
#include "core/runtime.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/fd_managed.h"

static int
test_pipe_create(int fds[2])
{
#ifdef _WIN32
    return _pipe(fds, 64 * 1024, _O_BINARY);
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

static ssize_t
test_fd_write(int fd, const void *buf, size_t len)
{
#ifdef _WIN32
    return (ssize_t)_write(fd, buf, (unsigned int)len);
#else
    return write(fd, buf, len);
#endif
}

// ============================================================================
// 1. Null owner returns Err.
// ============================================================================

static void
test_null_owner(void)
{
    auto r = n00b_fd_owner_read_all(nullptr);
    assert(n00b_result_is_err(r));
    printf("  [PASS] read_all: null owner returns Err\n");
}

// ============================================================================
// 2. Empty stream (write side closed before any bytes) returns Ok(empty).
// ============================================================================

static void
test_empty_stream(void)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    n00b_conduit_t *c  = rt->default_conduit;
    assert(c != nullptr);
    auto io_opt = n00b_conduit_default_backend(c);
    assert(n00b_option_is_set(io_opt));
    n00b_conduit_io_backend_t *io = n00b_option_get(io_opt);

    int fds[2];
    assert(test_pipe_create(fds) == 0);

    // Close the write side immediately to trigger EOF on the read end.
    test_fd_close(fds[1]);

    auto manage_r = n00b_conduit_fd_manage(c, io, fds[0], true);
    assert(n00b_result_is_ok(manage_r));
    n00b_conduit_fd_owner_t *owner = n00b_result_get(manage_r);

    auto r = n00b_fd_owner_read_all(owner);
    assert(n00b_result_is_ok(r));
    n00b_buffer_t *buf = n00b_result_get(r);
    assert(buf != nullptr);
    assert(buf->byte_len == 0);

    n00b_conduit_fd_owner_close(owner);
    printf("  [PASS] read_all: empty stream returns empty buffer\n");
}

// ============================================================================
// 3. Small payload (single chunk) round-trip.
// ============================================================================

static void
test_small_payload(void)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    n00b_conduit_t *c  = rt->default_conduit;
    auto io_opt = n00b_conduit_default_backend(c);
    assert(n00b_option_is_set(io_opt));
    n00b_conduit_io_backend_t *io = n00b_option_get(io_opt);

    int fds[2];
    assert(test_pipe_create(fds) == 0);

    const char *payload  = "hello, n00b_fd_owner_read_all!";
    size_t      pay_len  = strlen(payload);

    // Write the payload, then close the write side to trigger EOF.
    ssize_t w = test_fd_write(fds[1], payload, pay_len);
    assert(w == (ssize_t)pay_len);
    test_fd_close(fds[1]);

    auto manage_r = n00b_conduit_fd_manage(c, io, fds[0], true);
    assert(n00b_result_is_ok(manage_r));
    n00b_conduit_fd_owner_t *owner = n00b_result_get(manage_r);

    auto r = n00b_fd_owner_read_all(owner);
    assert(n00b_result_is_ok(r));
    n00b_buffer_t *buf = n00b_result_get(r);
    assert(buf != nullptr);
    assert(buf->byte_len == pay_len);
    assert(memcmp(buf->data, payload, pay_len) == 0);

    n00b_conduit_fd_owner_close(owner);
    printf("  [PASS] read_all: small payload round-trips (%zu bytes)\n",
           pay_len);
}

// ============================================================================
// 4. Multi-chunk payload aggregated into one buffer.
//
// Writes a payload larger than the IO thread's per-poll read budget
// (READ_BUF_SIZE = 4096) so the IO thread publishes multiple
// `n00b_buffer_t *` chunks and the helper has to concatenate them.
// ============================================================================

static void
test_multi_chunk_payload(void)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    n00b_conduit_t *c  = rt->default_conduit;
    auto io_opt = n00b_conduit_default_backend(c);
    assert(n00b_option_is_set(io_opt));
    n00b_conduit_io_backend_t *io = n00b_option_get(io_opt);

    int fds[2];
    assert(test_pipe_create(fds) == 0);

    // 32 KiB of deterministic bytes -- far exceeds the read budget.
    enum { PAYLOAD_LEN = 32 * 1024 };
    char *payload = (char *)malloc(PAYLOAD_LEN);
    assert(payload != nullptr);
    for (size_t i = 0; i < PAYLOAD_LEN; i++) {
        payload[i] = (char)(i & 0xff);
    }

    auto manage_r = n00b_conduit_fd_manage(c, io, fds[0], true);
    assert(n00b_result_is_ok(manage_r));
    n00b_conduit_fd_owner_t *owner = n00b_result_get(manage_r);

    // Let the managed read side drain concurrently so this test is
    // independent of the kernel's current pipe capacity.
    ssize_t total = 0;
    while (total < (ssize_t)PAYLOAD_LEN) {
        ssize_t w = test_fd_write(fds[1], payload + total,
                                   PAYLOAD_LEN - total);
        assert(w > 0);
        total += w;
    }
    test_fd_close(fds[1]);

    auto r = n00b_fd_owner_read_all(owner);
    assert(n00b_result_is_ok(r));
    n00b_buffer_t *buf = n00b_result_get(r);
    assert(buf != nullptr);
    assert(buf->byte_len == PAYLOAD_LEN);
    assert(memcmp(buf->data, payload, PAYLOAD_LEN) == 0);

    free(payload);
    n00b_conduit_fd_owner_close(owner);
    printf("  [PASS] read_all: 32 KiB multi-chunk payload round-trips\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("test_fd_owner_read_all:\n");
    fflush(stdout);

    test_null_owner();
    fflush(stdout);
    test_empty_stream();
    fflush(stdout);
    test_small_payload();
    fflush(stdout);
    test_multi_chunk_payload();
    fflush(stdout);

    printf("All fd_owner_read_all tests passed.\n");
    n00b_shutdown();
    return 0;
}

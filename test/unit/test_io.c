/*
 * test_io.c — Tests for conduit IO backend lifecycle and event delivery.
 *
 * Tests use a pipe pair to verify FD readability detection through the
 * platform-default IO backend.
 */

#include <stdio.h>
#include <assert.h>
#ifdef _WIN32
#include "internal/win32_sockets.h"
#else
#include <unistd.h>
#endif
#include <string.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "core/alloc.h"
#include "core/runtime.h"

// ============================================================================
// 1. IO backend create / destroy
// ============================================================================

typedef struct {
    base_socket_t read_fd;
    base_socket_t write_fd;
} test_io_pair_t;

#ifdef _WIN32
static void
test_close_socket_if_valid(SOCKET s)
{
    if (s != INVALID_SOCKET) {
        closesocket(s);
    }
}

static bool
test_io_pair_create(test_io_pair_t *pair)
{
    SOCKET listener = INVALID_SOCKET;
    SOCKET reader   = INVALID_SOCKET;
    SOCKET writer   = INVALID_SOCKET;

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        goto fail;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;

    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        goto fail;
    }

    int addr_len = sizeof(addr);
    if (getsockname(listener, (struct sockaddr *)&addr, &addr_len) == SOCKET_ERROR) {
        goto fail;
    }

    if (listen(listener, 1) == SOCKET_ERROR) {
        goto fail;
    }

    writer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (writer == INVALID_SOCKET) {
        goto fail;
    }

    if (connect(writer, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        goto fail;
    }

    reader = accept(listener, NULL, NULL);
    if (reader == INVALID_SOCKET) {
        goto fail;
    }

    closesocket(listener);
    pair->read_fd  = reader;
    pair->write_fd = writer;
    return true;

fail:
    test_close_socket_if_valid(reader);
    test_close_socket_if_valid(writer);
    test_close_socket_if_valid(listener);
    return false;
}

static void
test_io_pair_write(test_io_pair_t *pair, const char *data, size_t len)
{
    assert(send(pair->write_fd, data, (int)len, 0) == (int)len);
}

static void
test_io_pair_close(test_io_pair_t *pair)
{
    test_close_socket_if_valid(pair->read_fd);
    test_close_socket_if_valid(pair->write_fd);
}
#else
static bool
test_io_pair_create(test_io_pair_t *pair)
{
    int fds[2];
    if (pipe(fds) != 0) {
        return false;
    }

    pair->read_fd  = fds[0];
    pair->write_fd = fds[1];
    return true;
}

static void
test_io_pair_write(test_io_pair_t *pair, const char *data, size_t len)
{
    (void)write(pair->write_fd, data, len);
}

static void
test_io_pair_close(test_io_pair_t *pair)
{
    close(pair->read_fd);
    close(pair->write_fd);
}
#endif

static void
test_io_create_destroy(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);
    assert(io != nullptr);

    n00b_string_t *name = n00b_conduit_io_name(io);
    assert(name->data != nullptr);
    printf("    (backend: %.*s)\n", (int)name->u8_bytes, name->data);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] IO backend create/destroy\n");
}

// ============================================================================
// 2. Watch a pipe FD for readability
// ============================================================================

static void
test_io_watch_pipe(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    test_io_pair_t pair;
    assert(test_io_pair_create(&pair));

    // Watch read end for readability.
    n00b_result_t(n00b_conduit_topic_base_t *) tr =
        n00b_conduit_io_watch(io, pair.read_fd, N00B_CONDUIT_IO_READ, nullptr);
    assert(n00b_result_is_ok(tr));

    // Write some data so the read end becomes readable.
    const char *msg = "hello";
    test_io_pair_write(&pair, msg, strlen(msg));

    // Poll — should get at least 1 event.
    auto poll_r = n00b_conduit_io_poll(io, 100);
    assert(n00b_result_is_ok(poll_r));
    int n = n00b_result_get(poll_r);
    assert(n >= 1);

    // Clean up.
    n00b_conduit_io_unwatch(io, pair.read_fd);
    test_io_pair_close(&pair);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] watch pipe FD\n");
}

// ============================================================================
// 3. Unwatch removes FD
// ============================================================================

static void
test_io_unwatch(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    test_io_pair_t pair;
    assert(test_io_pair_create(&pair));

    n00b_conduit_io_watch(io, pair.read_fd, N00B_CONDUIT_IO_READ, nullptr);
    bool ok = n00b_conduit_io_unwatch(io, pair.read_fd);
    assert(ok);

    // Write data. Poll should return 0 since we unwatched.
    test_io_pair_write(&pair, "x", 1);
    auto poll_r2 = n00b_conduit_io_poll(io, 50);
    assert(n00b_result_is_ok(poll_r2));
    int n = n00b_result_get(poll_r2);
    assert(n == 0);

    test_io_pair_close(&pair);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] unwatch removes FD\n");
}

// ============================================================================
// 4. Shutdown prevents new watches
// ============================================================================

static void
test_io_shutdown(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    n00b_conduit_io_shutdown(io);

    test_io_pair_t pair;
    assert(test_io_pair_create(&pair));

    n00b_result_t(n00b_conduit_topic_base_t *) tr =
        n00b_conduit_io_watch(io, pair.read_fd, N00B_CONDUIT_IO_READ, nullptr);
    assert(n00b_result_is_err(tr));
    assert(n00b_result_get_err(tr) == N00B_CONDUIT_ERR_SHUTDOWN);

    test_io_pair_close(&pair);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] shutdown prevents watches\n");
}

// ============================================================================
// 5. Null arg handling
// ============================================================================

static void
test_io_null_args(void)
{
    // Null backend.
    assert(n00b_result_is_err(n00b_conduit_io_poll(nullptr, 0)));
    n00b_conduit_io_run(nullptr);   // Should not crash.
    n00b_conduit_io_shutdown(nullptr); // Should not crash.
    n00b_conduit_io_destroy(nullptr);  // Should not crash.

    printf("  [PASS] null arg handling\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_io:\n");
    fflush(stdout);

    test_io_create_destroy();
    fflush(stdout);
    test_io_watch_pipe();
    fflush(stdout);
    test_io_unwatch();
    fflush(stdout);
    test_io_shutdown();
    fflush(stdout);
    test_io_null_args();
    fflush(stdout);

    printf("All IO tests passed.\n");
    n00b_shutdown();
    return 0;
}

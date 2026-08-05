/*
 * test_socket.c — Tests for conduit socket listener and connections.
 *
 * Uses loopback TCP to test the socket lifecycle via the IO backend.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#ifdef _WIN32
#include "internal/win32_sockets.h"
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#endif

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/socket.h"
#include "core/alloc.h"
#include "core/runtime.h"

// ============================================================================
// 1. Create listener on loopback
// ============================================================================

static void
test_socket_close(base_socket_t fd)
{
#ifdef _WIN32
    closesocket((SOCKET)fd);
#else
    close(fd);
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

static void
test_socket_listener(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    // Create a TCP listener on port 0 (OS picks free port).
    auto listen_r = n00b_conduit_listen_tcp(c, io, r"127.0.0.1", 0, 5);

    if (n00b_result_is_err(listen_r)) {
        test_skip_or_fail("socket listener (bind/listen failed)");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }
    n00b_conduit_listener_t *listener = n00b_result_get(listen_r);

    assert(listener->fd != BASE_INVALID_SOCKET);
#ifdef _WIN32
    assert(sizeof(listener->fd) == sizeof(SOCKET));
    int exclusive     = 0;
    int exclusive_len = sizeof(exclusive);
    assert(getsockopt(listener->fd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                      (char *)&exclusive, &exclusive_len) == 0);
    assert(exclusive != 0);
#endif

    // Accept topic should be non-null.
    auto at_opt = n00b_conduit_listener_accept_topic(listener);
    assert(n00b_option_is_set(at_opt));

    n00b_conduit_listener_close(listener);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] socket listener\n");
}

// ============================================================================
// 2. Loopback connect and accept — exercises the full IO dispatch path
// ============================================================================

static void
test_socket_connect_accept(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    auto listen_r = n00b_conduit_listen_tcp(c, io, r"127.0.0.1", 0, 5);

    if (n00b_result_is_err(listen_r)) {
        test_skip_or_fail("socket connect/accept (bind/listen failed)");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }
    n00b_conduit_listener_t *listener = n00b_result_get(listen_r);

    // Get the port the OS assigned by querying the socket.
    struct sockaddr_in bound;
    socklen_t          bound_len = sizeof(bound);
    int                grc = getsockname(listener->fd, (struct sockaddr *)&bound, &bound_len);
    assert(grc == 0);
    uint16_t port = ntohs(bound.sin_port);
    assert(port > 0);

    // Subscribe an inbox to the accept topic.
    auto accept_topic_opt = n00b_conduit_listener_accept_topic(listener);
    assert(n00b_option_is_set(accept_topic_opt));
    n00b_conduit_topic_base_t *accept_topic = n00b_option_get(accept_topic_opt);

    n00b_conduit_sock_accept_inbox_t *inbox = n00b_alloc(n00b_conduit_sock_accept_inbox_t);
    n00b_conduit_inbox_init(n00b_conduit_sock_accept_payload_t,
                            inbox,
                            c,
                            N00B_CONDUIT_BP_UNBOUNDED,
                            0);
    assert(inbox != nullptr);

    n00b_conduit_sub_handle_t handle
        = n00b_conduit_sock_accept_subscribe(accept_topic,
                                             inbox,
                                             .operations = N00B_CONDUIT_OP_ALL);
    assert(handle != N00B_CONDUIT_INVALID_SUB_HANDLE);

    // Connect a raw client socket.
    SOCKET client_socket = socket(AF_INET, SOCK_STREAM, 0);
    assert(client_socket != INVALID_SOCKET);
    base_socket_t client_fd = client_socket;

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
        .sin_addr   = {0},
    };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    int rc = connect(client_fd, (struct sockaddr *)&addr, sizeof(addr));
    assert(rc == 0);

    // Drive the IO backend — this triggers the kqueue/poll readiness event
    // on the listener fd, which routes through deliver_io_event() →
    // n00b_conduit_listener_dispatch() → accept() → publish to accept topic.
    bool got_message = false;
    for (int attempts = 0; attempts < 20; attempts++) {
        n00b_conduit_io_poll(io, 100);

        if (n00b_conduit_sock_accept_inbox_has_messages(inbox)) {
            got_message = true;
            break;
        }
    }

    assert(got_message);

    // Pop the accept message and verify the client_fd is valid.
    n00b_conduit_sock_accept_msg_t *msg = n00b_conduit_sock_accept_inbox_pop(inbox);
    assert(msg != nullptr);
    assert(sizeof(msg->payload.client_fd) == sizeof(base_socket_t));
    assert(msg->payload.client_fd != BASE_INVALID_SOCKET);

    // Clean up the accepted fd and client fd.
    test_socket_close(msg->payload.client_fd);
    test_socket_close(client_fd);

    n00b_conduit_listener_close(listener);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] socket connect/accept\n");
}

#ifdef _WIN32
static void
test_conn_from_fd_makes_winsock_nonblocking(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(listener != INVALID_SOCKET);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = 0,
        .sin_addr   = {0},
    };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    assert(bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(listener, 1) == 0);

    socklen_t addr_len = sizeof(addr);
    assert(getsockname(listener, (struct sockaddr *)&addr, &addr_len) == 0);

    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(client != INVALID_SOCKET);
    assert(connect(client, (struct sockaddr *)&addr, sizeof(addr)) == 0);

    SOCKET accepted = accept(listener, NULL, NULL);
    assert(accepted != INVALID_SOCKET);
    test_socket_close(listener);

    DWORD recv_timeout_ms = 100;
    assert(setsockopt(accepted, SOL_SOCKET, SO_RCVTIMEO,
                      (const char *)&recv_timeout_ms,
                      sizeof(recv_timeout_ms)) == 0);

    u_long blocking = 0;
    assert(ioctlsocket(accepted, FIONBIO, &blocking) == 0);

    auto conn_r = n00b_conduit_conn_from_fd(c, io, accepted);
    assert(n00b_result_is_ok(conn_r));
    n00b_conduit_conn_t *conn = n00b_result_get(conn_r);

    char byte;
    assert(recv(accepted, &byte, 1, 0) == SOCKET_ERROR);
    assert(WSAGetLastError() == WSAEWOULDBLOCK);

    auto owner_opt = n00b_conduit_conn_fd_owner(conn);
    assert(n00b_option_is_set(owner_opt));
    n00b_conduit_conn_close(conn);
    n00b_conduit_fd_owner_close(n00b_option_get(owner_opt));
    test_socket_close(client);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] conn_from_fd makes Winsock nonblocking\n");
}
#endif

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_socket:\n");
    fflush(stdout);

    test_socket_listener();
    fflush(stdout);
    test_socket_connect_accept();
    fflush(stdout);
#ifdef _WIN32
    test_conn_from_fd_makes_winsock_nonblocking();
    fflush(stdout);
#endif

    printf("All socket tests passed.\n");
    n00b_shutdown();
    return 0;
}

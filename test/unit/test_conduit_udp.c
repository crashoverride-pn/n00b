/*
 * test_conduit_udp.c — Tests for the UDP datagram conduit.
 *
 * Loopback bind + send + recv via the IO backend's dispatch path; verifies
 * that the recv topic delivers a typed n00b_conduit_udp_datagram_t to a
 * subscribed inbox carrying the peer address and payload.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/socket_udp.h"
#include "core/alloc.h"
#include "core/runtime.h"

static uint16_t
local_port_of(n00b_conduit_udp_t *u)
{
    struct sockaddr_storage ss;
    socklen_t               sslen = sizeof(ss);
    auto                    r     = n00b_conduit_udp_local_addr(u,
                                          (struct sockaddr *)&ss,
                                          &sslen);
    assert(n00b_result_is_ok(r));
    assert(ss.ss_family == AF_INET);
    return ntohs(((struct sockaddr_in *)&ss)->sin_port);
}

/* ============================================================================
 * 1. Bind on an ephemeral port + close cleanly + close is idempotent
 * ============================================================================ */

static void
test_udp_bind_close(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    auto br = n00b_conduit_udp_bind(c, io, "127.0.0.1", 0);
    if (n00b_result_is_err(br)) {
        printf("  [SKIP] udp bind/close (bind failed)\n");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }
    n00b_conduit_udp_t *u = n00b_result_get(br);
    assert(u->fd != BASE_INVALID_SOCKET);
    assert(n00b_conduit_udp_recv_topic(u) != nullptr);
    assert(local_port_of(u) > 0);

    n00b_conduit_udp_close(u);
    assert(u->fd == BASE_INVALID_SOCKET);
    /* Idempotent. */
    n00b_conduit_udp_close(u);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] udp bind + close (idempotent)\n");
}

/* ============================================================================
 * 2. Loopback send/recv: two UDP sockets exchange a datagram
 * ============================================================================ */

static void
test_udp_loopback(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    auto sr = n00b_conduit_udp_bind(c, io, "127.0.0.1", 0);
    if (n00b_result_is_err(sr)) {
        printf("  [SKIP] udp loopback (server bind failed)\n");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }
    n00b_conduit_udp_t *server = n00b_result_get(sr);
    uint16_t            sport  = local_port_of(server);

    auto cur = n00b_conduit_udp_bind(c, io, "127.0.0.1", 0);
    if (n00b_result_is_err(cur)) {
        printf("  [SKIP] udp loopback (client bind failed)\n");
        n00b_conduit_udp_close(server);
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }
    n00b_conduit_udp_t *client = n00b_result_get(cur);
    uint16_t            cport  = local_port_of(client);

    /* Subscribe the server's recv topic. */
    n00b_conduit_topic_base_t *t = n00b_conduit_udp_recv_topic(server);
    assert(t != nullptr);
    n00b_conduit_udp_datagram_inbox_t *inbox = n00b_conduit_udp_inbox_new(c);
    assert(inbox != nullptr);
    n00b_conduit_sub_handle_t sh =
        n00b_conduit_udp_subscribe(t, inbox,
                                   .operations = N00B_CONDUIT_OP_ALL);
    assert(sh != N00B_CONDUIT_INVALID_SUB_HANDLE);

    /* Send a datagram from client → server. */
    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port   = htons(sport),
        .sin_addr   = {0},
    };
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);

    static const uint8_t payload[] = "n00b/quic udp probe";
    auto                 send_r =
        n00b_conduit_udp_send(client,
                              (const struct sockaddr *)&dst,
                              sizeof(dst),
                              payload,
                              sizeof(payload) - 1);
    assert(n00b_result_is_ok(send_r));
    assert(n00b_result_get(send_r) == sizeof(payload) - 1);

    /* Drive the IO backend until the recv shows up (or give up). */
    bool got = false;
    for (int attempts = 0; attempts < 20 && !got; attempts++) {
        n00b_conduit_io_poll(io, 100);
        got = n00b_conduit_udp_inbox_has_messages(inbox);
    }
    assert(got);

    /* Pop and validate. */
    n00b_conduit_udp_datagram_msg_t *msg =
        n00b_conduit_udp_inbox_pop(inbox);
    assert(msg != nullptr);
    assert(msg->payload.len == sizeof(payload) - 1);
    assert(msg->payload.bytes != nullptr);
    assert(memcmp(msg->payload.bytes, payload, sizeof(payload) - 1) == 0);
    /* Peer should be 127.0.0.1:cport. */
    assert(msg->payload.peer.ss_family == AF_INET);
    struct sockaddr_in *peer4 = (struct sockaddr_in *)&msg->payload.peer;
    assert(ntohs(peer4->sin_port) == cport);
    assert(peer4->sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    /* Stats updated. */
    assert(server->rx_packets == 1);
    assert(server->rx_bytes == sizeof(payload) - 1);
    assert(client->tx_packets == 1);
    assert(client->tx_bytes == sizeof(payload) - 1);

    n00b_conduit_udp_close(client);
    n00b_conduit_udp_close(server);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] udp loopback send/recv\n");
}

/* ============================================================================
 * 3. udp_send error paths
 * ============================================================================ */

static void
test_udp_send_errors(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    auto br = n00b_conduit_udp_bind(c, io, "127.0.0.1", 0);
    if (n00b_result_is_err(br)) {
        printf("  [SKIP] udp send errors (bind failed)\n");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }
    n00b_conduit_udp_t *u = n00b_result_get(br);

    /* NULL peer. */
    auto r = n00b_conduit_udp_send(u, nullptr, 0, (const uint8_t *)"x", 1);
    assert(n00b_result_is_err(r));

    /* NULL bytes with non-zero len. */
    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port   = htons(1234),
        .sin_addr   = {0},
    };
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);
    r = n00b_conduit_udp_send(u, (const struct sockaddr *)&dst, sizeof(dst),
                              nullptr, 5);
    assert(n00b_result_is_err(r));

    /* Send after close. */
    n00b_conduit_udp_close(u);
    r = n00b_conduit_udp_send(u, (const struct sockaddr *)&dst, sizeof(dst),
                              (const uint8_t *)"x", 1);
    assert(n00b_result_is_err(r));

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] udp send error paths\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_conduit_udp:\n");
    fflush(stdout);

    test_udp_bind_close();
    fflush(stdout);
    test_udp_loopback();
    fflush(stdout);
    test_udp_send_errors();
    fflush(stdout);

    printf("All udp conduit tests passed.\n");
    n00b_shutdown();
    return 0;
}

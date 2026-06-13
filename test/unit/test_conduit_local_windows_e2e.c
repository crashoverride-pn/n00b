/*
 * test_conduit_local_windows_e2e.c - Windows named local IPC e2e test.
 *
 * This target is Windows-only and uses only the public portable local IPC API.
 * Phase 3 covers named-pipe n00b_buffer_t data exchange and terminal status
 * behavior behind the portable local IPC API.
 */

#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "conduit/local.h"
#include "core/gc.h"
#include "core/platform.h"
#include "core/runtime.h"

static n00b_conduit_t *
make_conduit(void)
{
    auto cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    return n00b_result_get(cr);
}

static void
assert_buffer_eq(n00b_buffer_t *buf, const char *expected, size_t len)
{
    assert(buf != nullptr);
    assert(buf->byte_len == len);
    assert(memcmp(buf->data, expected, len) == 0);
}

static void
assert_buffer_bytes(n00b_buffer_t *buf, const uint8_t *expected, size_t len)
{
    assert(buf != nullptr);
    assert(buf->byte_len == len);
    assert(memcmp(buf->data, expected, len) == 0);
}

static void
fill_pattern(uint8_t *bytes, size_t len)
{
    assert(bytes != nullptr);
    for (size_t i = 0; i < len; i++) {
        bytes[i] = (uint8_t)((i * 31) ^ (i >> 3));
    }
}

static n00b_conduit_message_t(n00b_buffer_t *) *
wait_for_buffer_msg(n00b_conduit_inbox_t(n00b_buffer_t *) *inbox)
{
    for (int i = 0; i < 400; i++) {
        if (n00b_conduit_inbox_has_msg(n00b_buffer_t *, inbox)) {
            break;
        }
        base_nanosleep_ns(5000000ULL);
    }

    assert(n00b_conduit_inbox_has_msg(n00b_buffer_t *, inbox));
    n00b_conduit_message_t(n00b_buffer_t *) *msg =
        n00b_conduit_inbox_pop_msg(n00b_buffer_t *, inbox);
    assert(msg != nullptr);
    assert(msg->payload != nullptr);
    return msg;
}

static n00b_conduit_local_status_msg_t *
wait_for_windows_status(n00b_conduit_local_status_inbox_t *inbox)
{
    for (int i = 0; i < 400; i++) {
        if (n00b_conduit_local_status_inbox_has_messages(inbox)) {
            break;
        }
        base_nanosleep_ns(5000000ULL);
    }

    assert(n00b_conduit_local_status_inbox_has_messages(inbox));
    n00b_conduit_local_status_msg_t *msg =
        n00b_conduit_local_status_inbox_pop(inbox);
    assert(msg != nullptr);
    return msg;
}

static void
test_local_windows_public_header_shape(void)
{
    n00b_conduit_local_backend_t backend = N00B_CONDUIT_LOCAL_WINDOWS_NAMED;
    assert(backend == N00B_CONDUIT_LOCAL_WINDOWS_NAMED);

    n00b_conduit_local_peer_t peer = {
        .backend         = backend,
        .pid             = n00b_option_none(uint64_t),
        .uid             = n00b_option_none(uint64_t),
        .gid             = n00b_option_none(uint64_t),
        .code_signing_id = n00b_option_none(n00b_string_t *),
    };
    assert(peer.backend == N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(n00b_option_is_set(peer.pid) == false);
    assert(n00b_option_is_set(peer.uid) == false);
    assert(n00b_option_is_set(peer.gid) == false);
    assert(n00b_option_is_set(peer.code_signing_id) == false);
}

static n00b_conduit_local_accept_msg_t *
wait_for_windows_accept(n00b_conduit_local_accept_inbox_t *inbox)
{
    for (int i = 0; i < 400; i++) {
        if (n00b_conduit_local_accept_inbox_has_messages(inbox)) {
            break;
        }
        base_nanosleep_ns(5000000ULL);
    }

    assert(n00b_conduit_local_accept_inbox_has_messages(inbox));
    n00b_conduit_local_accept_msg_t *msg =
        n00b_conduit_local_accept_inbox_pop(inbox);
    assert(msg != nullptr);
    assert(msg->payload.conn != nullptr);
    assert(msg->payload.peer.backend == N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(n00b_option_is_set(msg->payload.peer.uid) == false);
    assert(n00b_option_is_set(msg->payload.peer.gid) == false);
    assert(n00b_option_is_set(msg->payload.peer.code_signing_id) == false);
    return msg;
}

typedef struct {
    n00b_conduit_t                *c;
    n00b_conduit_local_listener_t *listener;
    n00b_conduit_local_conn_t     *client;
    n00b_conduit_local_conn_t     *server;
} local_windows_pair_t;

static local_windows_pair_t
make_local_windows_pair(n00b_string_t               *name,
                        n00b_conduit_local_backend_t backend)
{
    local_windows_pair_t pair = {};

    pair.c = make_conduit();

    auto lr = n00b_conduit_local_listen(pair.c, name, .backend = backend);
    assert(n00b_result_is_ok(lr));
    pair.listener = n00b_result_get(lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_local_listener_accept_topic_typed(pair.listener);
    assert(accept_topic != nullptr);
    n00b_conduit_local_accept_inbox_t *accept_inbox =
        n00b_conduit_local_accept_inbox_new(pair.c);
    n00b_conduit_local_accept_subscribe(accept_topic, accept_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto cr = n00b_conduit_local_connect(pair.c, name, .backend = backend);
    assert(n00b_result_is_ok(cr));
    pair.client = n00b_result_get(cr);

    n00b_conduit_local_accept_msg_t *accepted =
        wait_for_windows_accept(accept_inbox);
    pair.server = accepted->payload.conn;
    assert(pair.server != nullptr);

    return pair;
}

static void
close_local_windows_pair(local_windows_pair_t *pair)
{
    assert(pair != nullptr);
    n00b_conduit_local_conn_close(pair->server);
    n00b_conduit_local_conn_close(pair->client);
    n00b_conduit_local_listener_close(pair->listener);
    n00b_conduit_destroy(pair->c);
}

static void
write_and_expect(n00b_conduit_topic_t(n00b_buffer_t *) *write_topic,
                 n00b_conduit_topic_t(n00b_buffer_t *) *read_topic,
                 const char                            *bytes,
                 size_t                                 len)
{
    n00b_buffer_t *out = n00b_buffer_from_bytes((char *)bytes, (int64_t)len);
    auto wr = n00b_conduit_write(n00b_buffer_t *, write_topic, out,
                                 .sync = false);
    assert(n00b_result_is_ok(wr));

    auto rr = n00b_conduit_read(n00b_buffer_t *, read_topic,
                                .timeout_ms = 2000);
    assert(n00b_result_is_ok(rr));
    n00b_conduit_message_t(n00b_buffer_t *) *read_msg = n00b_result_get(rr);
    assert_buffer_eq(read_msg->payload, bytes, len);
}

static void
test_local_windows_absent_endpoint(void)
{
    n00b_conduit_t *c    = make_conduit();
    n00b_string_t  *name = r"wp004-windows-absent";

    auto cr = n00b_conduit_local_connect(
        c, name, .backend = N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(n00b_result_is_err(cr));
    assert(n00b_result_get_err(cr) == N00B_CONDUIT_ERR_NOT_FOUND);

    n00b_conduit_destroy(c);
}

static void
test_local_windows_explicit_accept(void)
{
    n00b_conduit_t *c    = make_conduit();
    n00b_string_t  *name = r"wp004-windows-explicit-accept";

    auto lr = n00b_conduit_local_listen(
        c, name, .backend = N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_local_listener_accept_topic_typed(listener);
    assert(accept_topic != nullptr);
    n00b_conduit_local_accept_inbox_t *accept_inbox =
        n00b_conduit_local_accept_inbox_new(c);
    n00b_conduit_local_accept_subscribe(accept_topic, accept_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto cr = n00b_conduit_local_connect(
        c, name, .backend = N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(n00b_result_is_ok(cr));
    n00b_conduit_local_conn_t *client = n00b_result_get(cr);
    n00b_conduit_local_accept_msg_t *accepted =
        wait_for_windows_accept(accept_inbox);

    n00b_conduit_topic_t(n00b_buffer_t *) *client_read =
        n00b_conduit_local_conn_read_topic_typed(client);
    n00b_conduit_topic_t(n00b_buffer_t *) *client_write =
        n00b_conduit_local_conn_write_topic_typed(client);
    n00b_conduit_topic_t(n00b_buffer_t *) *server_read =
        n00b_conduit_local_conn_read_topic_typed(accepted->payload.conn);
    n00b_conduit_topic_t(n00b_buffer_t *) *server_write =
        n00b_conduit_local_conn_write_topic_typed(accepted->payload.conn);
    assert(client_read != nullptr);
    assert(client_write != nullptr);
    assert(server_read != nullptr);
    assert(server_write != nullptr);

    n00b_conduit_local_conn_close(accepted->payload.conn);
    n00b_conduit_local_conn_close(client);
    n00b_conduit_local_listener_close(listener);
    n00b_conduit_destroy(c);
}

static void
test_local_windows_multiple_clients(void)
{
    n00b_conduit_t *c    = make_conduit();
    n00b_string_t  *name = r"wp004-windows-multiple-clients";

    auto lr = n00b_conduit_local_listen(
        c, name, .backend = N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_local_listener_accept_topic_typed(listener);
    assert(accept_topic != nullptr);
    n00b_conduit_local_accept_inbox_t *accept_inbox =
        n00b_conduit_local_accept_inbox_new(c);
    n00b_conduit_local_accept_subscribe(accept_topic, accept_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto c1r = n00b_conduit_local_connect(
        c, name, .backend = N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(n00b_result_is_ok(c1r));
    n00b_conduit_local_conn_t *client1 = n00b_result_get(c1r);
    n00b_conduit_local_accept_msg_t *accepted1 =
        wait_for_windows_accept(accept_inbox);

    auto c2r = n00b_conduit_local_connect(
        c, name, .backend = N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(n00b_result_is_ok(c2r));
    n00b_conduit_local_conn_t *client2 = n00b_result_get(c2r);
    n00b_conduit_local_accept_msg_t *accepted2 =
        wait_for_windows_accept(accept_inbox);

    assert(accepted1->payload.conn != accepted2->payload.conn);
    assert(accepted1->payload.peer.backend == N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(accepted2->payload.peer.backend == N00B_CONDUIT_LOCAL_WINDOWS_NAMED);

    n00b_conduit_topic_t(n00b_buffer_t *) *client1_write =
        n00b_conduit_local_conn_write_topic_typed(client1);
    n00b_conduit_topic_t(n00b_buffer_t *) *client1_read =
        n00b_conduit_local_conn_read_topic_typed(client1);
    n00b_conduit_topic_t(n00b_buffer_t *) *server1_write =
        n00b_conduit_local_conn_write_topic_typed(accepted1->payload.conn);
    n00b_conduit_topic_t(n00b_buffer_t *) *server1_read =
        n00b_conduit_local_conn_read_topic_typed(accepted1->payload.conn);
    n00b_conduit_topic_t(n00b_buffer_t *) *client2_write =
        n00b_conduit_local_conn_write_topic_typed(client2);
    n00b_conduit_topic_t(n00b_buffer_t *) *client2_read =
        n00b_conduit_local_conn_read_topic_typed(client2);
    n00b_conduit_topic_t(n00b_buffer_t *) *server2_write =
        n00b_conduit_local_conn_write_topic_typed(accepted2->payload.conn);
    n00b_conduit_topic_t(n00b_buffer_t *) *server2_read =
        n00b_conduit_local_conn_read_topic_typed(accepted2->payload.conn);
    assert(client1_write != nullptr && client1_read != nullptr);
    assert(server1_write != nullptr && server1_read != nullptr);
    assert(client2_write != nullptr && client2_read != nullptr);
    assert(server2_write != nullptr && server2_read != nullptr);

    write_and_expect(client1_write, server1_read, "client-one", 10);
    write_and_expect(client2_write, server2_read, "client-two", 10);
    write_and_expect(server1_write, client1_read, "server-one", 10);
    write_and_expect(server2_write, client2_read, "server-two", 10);

    n00b_conduit_local_conn_close(accepted1->payload.conn);
    n00b_conduit_local_conn_close(accepted2->payload.conn);
    n00b_conduit_local_conn_close(client1);
    n00b_conduit_local_conn_close(client2);
    n00b_conduit_local_listener_close(listener);
    n00b_conduit_destroy(c);
}

static void
test_local_windows_auto_ping_pong(void)
{
    local_windows_pair_t pair = make_local_windows_pair(
        r"wp004-windows-auto-ping-pong", N00B_CONDUIT_LOCAL_AUTO);

    n00b_conduit_topic_t(n00b_buffer_t *) *client_write =
        n00b_conduit_local_conn_write_topic_typed(pair.client);
    n00b_conduit_topic_t(n00b_buffer_t *) *client_read =
        n00b_conduit_local_conn_read_topic_typed(pair.client);
    n00b_conduit_topic_t(n00b_buffer_t *) *server_write =
        n00b_conduit_local_conn_write_topic_typed(pair.server);
    n00b_conduit_topic_t(n00b_buffer_t *) *server_read =
        n00b_conduit_local_conn_read_topic_typed(pair.server);
    assert(client_write != nullptr && client_read != nullptr);
    assert(server_write != nullptr && server_read != nullptr);

    write_and_expect(client_write, server_read, "auto-ping", 9);
    write_and_expect(server_write, client_read, "auto-pong", 9);

    close_local_windows_pair(&pair);
}

static void
test_local_windows_ping_pong(void)
{
    n00b_conduit_t *c    = make_conduit();
    n00b_string_t  *name = r"wp004-windows-ping-pong";

    auto lr = n00b_conduit_local_listen(
        c, name, .backend = N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_local_listener_accept_topic_typed(listener);
    n00b_conduit_local_accept_inbox_t *accept_inbox =
        n00b_conduit_local_accept_inbox_new(c);
    n00b_conduit_local_accept_subscribe(accept_topic, accept_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto cr = n00b_conduit_local_connect(
        c, name, .backend = N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(n00b_result_is_ok(cr));
    n00b_conduit_local_conn_t *client = n00b_result_get(cr);
    n00b_conduit_local_accept_msg_t *accepted =
        wait_for_windows_accept(accept_inbox);
    n00b_conduit_local_conn_t *server = accepted->payload.conn;

    n00b_conduit_topic_t(n00b_buffer_t *) *client_write =
        n00b_conduit_local_conn_write_topic_typed(client);
    n00b_conduit_topic_t(n00b_buffer_t *) *client_read =
        n00b_conduit_local_conn_read_topic_typed(client);
    n00b_conduit_topic_t(n00b_buffer_t *) *server_write =
        n00b_conduit_local_conn_write_topic_typed(server);
    n00b_conduit_topic_t(n00b_buffer_t *) *server_read =
        n00b_conduit_local_conn_read_topic_typed(server);
    assert(client_write != nullptr && client_read != nullptr);
    assert(server_write != nullptr && server_read != nullptr);

    n00b_buffer_t *ping = n00b_buffer_from_bytes("win-ping", 8);
    auto wr = n00b_conduit_write(n00b_buffer_t *, client_write, ping,
                                 .sync = false);
    assert(n00b_result_is_ok(wr));
    auto rr = n00b_conduit_read(n00b_buffer_t *, server_read,
                                .timeout_ms = 2000);
    assert(n00b_result_is_ok(rr));
    n00b_conduit_message_t(n00b_buffer_t *) *read_msg = n00b_result_get(rr);
    assert_buffer_eq(read_msg->payload, "win-ping", 8);

    n00b_buffer_t *pong = n00b_buffer_from_bytes("win-pong", 8);
    wr = n00b_conduit_write(n00b_buffer_t *, server_write, pong,
                            .sync = false);
    assert(n00b_result_is_ok(wr));
    rr = n00b_conduit_read(n00b_buffer_t *, client_read,
                           .timeout_ms = 2000);
    assert(n00b_result_is_ok(rr));
    read_msg = n00b_result_get(rr);
    assert_buffer_eq(read_msg->payload, "win-pong", 8);

    n00b_conduit_local_conn_close(server);
    n00b_conduit_local_conn_close(client);
    n00b_conduit_local_listener_close(listener);
    n00b_conduit_destroy(c);
}

static void
test_local_windows_repeated_close(void)
{
    local_windows_pair_t pair = make_local_windows_pair(
        r"wp004-windows-repeated-close", N00B_CONDUIT_LOCAL_WINDOWS_NAMED);

    n00b_conduit_topic_t(n00b_conduit_local_status_payload_t) *client_status =
        n00b_conduit_local_conn_status_topic_typed(pair.client);
    n00b_conduit_topic_t(n00b_conduit_local_status_payload_t) *server_status =
        n00b_conduit_local_conn_status_topic_typed(pair.server);
    n00b_conduit_local_status_inbox_t *client_status_inbox =
        n00b_conduit_local_status_inbox_new(pair.c);
    n00b_conduit_local_status_inbox_t *server_status_inbox =
        n00b_conduit_local_status_inbox_new(pair.c);
    n00b_conduit_local_status_subscribe(client_status, client_status_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);
    n00b_conduit_local_status_subscribe(server_status, server_status_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    n00b_conduit_local_conn_close(pair.client);
    n00b_conduit_local_conn_close(pair.client);
    n00b_conduit_local_conn_close(pair.server);
    n00b_conduit_local_conn_close(pair.server);
    n00b_conduit_local_listener_close(pair.listener);
    n00b_conduit_local_listener_close(pair.listener);

    n00b_conduit_local_status_msg_t *client_msg =
        wait_for_windows_status(client_status_inbox);
    assert(client_msg->payload.backend == N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(client_msg->payload.event == N00B_CONDUIT_LOCAL_CLOSED);

    n00b_conduit_local_status_msg_t *server_msg =
        wait_for_windows_status(server_status_inbox);
    assert(server_msg->payload.backend == N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(server_msg->payload.event == N00B_CONDUIT_LOCAL_CLOSED);

    base_nanosleep_ns(50000000ULL);
    assert(n00b_conduit_local_status_inbox_has_messages(client_status_inbox) ==
           false);
    assert(n00b_conduit_local_status_inbox_has_messages(server_status_inbox) ==
           false);

    n00b_conduit_destroy(pair.c);
}

static void
test_local_windows_large_message(void)
{
    n00b_conduit_t *c    = make_conduit();
    n00b_string_t  *name = r"wp004-windows-large-message";

    auto lr = n00b_conduit_local_listen(
        c, name, .backend = N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_local_listener_accept_topic_typed(listener);
    n00b_conduit_local_accept_inbox_t *accept_inbox =
        n00b_conduit_local_accept_inbox_new(c);
    n00b_conduit_local_accept_subscribe(accept_topic, accept_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto cr = n00b_conduit_local_connect(
        c, name, .backend = N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(n00b_result_is_ok(cr));
    n00b_conduit_local_conn_t *client = n00b_result_get(cr);
    n00b_conduit_local_accept_msg_t *accepted =
        wait_for_windows_accept(accept_inbox);
    n00b_conduit_local_conn_t *server = accepted->payload.conn;

    n00b_conduit_topic_t(n00b_buffer_t *) *client_write =
        n00b_conduit_local_conn_write_topic_typed(client);
    n00b_conduit_topic_t(n00b_buffer_t *) *server_read =
        n00b_conduit_local_conn_read_topic_typed(server);
    assert(client_write != nullptr && server_read != nullptr);

    size_t   len     = 131072;
    uint8_t *payload = n00b_alloc_array(uint8_t, len);
    fill_pattern(payload, len);

    n00b_buffer_t *out = n00b_buffer_from_bytes((char *)payload,
                                                (int64_t)len);
    auto wr = n00b_conduit_write(n00b_buffer_t *, client_write, out,
                                 .sync = false);
    assert(n00b_result_is_ok(wr));
    auto rr = n00b_conduit_read(n00b_buffer_t *, server_read,
                                .timeout_ms = 4000);
    assert(n00b_result_is_ok(rr));
    n00b_conduit_message_t(n00b_buffer_t *) *read_msg = n00b_result_get(rr);
    assert_buffer_bytes(read_msg->payload, payload, len);

    n00b_conduit_local_conn_close(server);
    n00b_conduit_local_conn_close(client);
    n00b_conduit_local_listener_close(listener);
    n00b_conduit_destroy(c);
}

static void
test_local_windows_many_sequential_messages(void)
{
    n00b_conduit_t *c    = make_conduit();
    n00b_string_t  *name = r"wp004-windows-sequential";

    auto lr = n00b_conduit_local_listen(
        c, name, .backend = N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_local_listener_accept_topic_typed(listener);
    n00b_conduit_local_accept_inbox_t *accept_inbox =
        n00b_conduit_local_accept_inbox_new(c);
    n00b_conduit_local_accept_subscribe(accept_topic, accept_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto cr = n00b_conduit_local_connect(
        c, name, .backend = N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(n00b_result_is_ok(cr));
    n00b_conduit_local_conn_t *client = n00b_result_get(cr);
    n00b_conduit_local_accept_msg_t *accepted =
        wait_for_windows_accept(accept_inbox);
    n00b_conduit_local_conn_t *server = accepted->payload.conn;

    n00b_conduit_topic_t(n00b_buffer_t *) *client_write =
        n00b_conduit_local_conn_write_topic_typed(client);
    n00b_conduit_topic_t(n00b_buffer_t *) *server_read =
        n00b_conduit_local_conn_read_topic_typed(server);
    assert(client_write != nullptr && server_read != nullptr);

    n00b_conduit_inbox_t(n00b_buffer_t *) *read_inbox =
        n00b_alloc_with_opts(n00b_conduit_inbox_t(n00b_buffer_t *),
                             &(n00b_alloc_opts_t){.allocator = c->allocator});
    n00b_conduit_inbox_init(n00b_buffer_t *, read_inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_sub_handle_t read_sub = n00b_conduit_subscribe(
        n00b_buffer_t *, server_read, read_inbox,
        .operations = N00B_CONDUIT_OP_ALL);
    assert(read_sub != N00B_CONDUIT_INVALID_SUB_HANDLE);

    const char *seq[] = {"one", "two-two", "three-three", "four"};
    size_t seq_len[] = {3, 7, 11, 4};
    for (int i = 0; i < 4; i++) {
        n00b_buffer_t *buf = n00b_buffer_from_bytes((char *)seq[i],
                                                    (int64_t)seq_len[i]);
        auto wr = n00b_conduit_write(n00b_buffer_t *, client_write, buf,
                                     .sync = false);
        assert(n00b_result_is_ok(wr));
    }

    for (int i = 0; i < 4; i++) {
        n00b_conduit_message_t(n00b_buffer_t *) *msg =
            wait_for_buffer_msg(read_inbox);
        assert_buffer_eq(msg->payload, seq[i], seq_len[i]);
    }

    n00b_conduit_sub_cancel(read_sub);
    n00b_conduit_local_conn_close(server);
    n00b_conduit_local_conn_close(client);
    n00b_conduit_local_listener_close(listener);
    n00b_conduit_destroy(c);
}

static void
test_local_windows_peer_disconnect_status(void)
{
    n00b_conduit_t *c    = make_conduit();
    n00b_string_t  *name = r"wp004-windows-peer-disconnect";

    auto lr = n00b_conduit_local_listen(
        c, name, .backend = N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_local_listener_accept_topic_typed(listener);
    n00b_conduit_local_accept_inbox_t *accept_inbox =
        n00b_conduit_local_accept_inbox_new(c);
    n00b_conduit_local_accept_subscribe(accept_topic, accept_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto cr = n00b_conduit_local_connect(
        c, name, .backend = N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(n00b_result_is_ok(cr));
    n00b_conduit_local_conn_t *client = n00b_result_get(cr);
    n00b_conduit_local_accept_msg_t *accepted =
        wait_for_windows_accept(accept_inbox);
    n00b_conduit_local_conn_t *server = accepted->payload.conn;

    n00b_conduit_topic_t(n00b_conduit_local_status_payload_t) *server_status =
        n00b_conduit_local_conn_status_topic_typed(server);
    n00b_conduit_local_status_inbox_t *status_inbox =
        n00b_conduit_local_status_inbox_new(c);
    n00b_conduit_local_status_subscribe(server_status, status_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    n00b_conduit_local_conn_close(client);
    n00b_conduit_local_status_msg_t *status_msg =
        wait_for_windows_status(status_inbox);
    assert(status_msg->payload.backend == N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(status_msg->payload.event == N00B_CONDUIT_LOCAL_CLOSED);

    base_nanosleep_ns(50000000ULL);
    assert(n00b_conduit_local_status_inbox_has_messages(status_inbox) == false);

    n00b_conduit_local_conn_close(server);
    n00b_conduit_local_listener_close(listener);
    n00b_conduit_destroy(c);
}

static void
test_local_windows_pending_close_and_gc(n00b_arena_t *arena)
{
    n00b_conduit_t *c    = make_conduit();
    n00b_string_t  *name = r"wp004-windows-pending-close-gc";

    auto lr = n00b_conduit_local_listen(
        c, name, .backend = N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_local_listener_accept_topic_typed(listener);
    n00b_conduit_local_accept_inbox_t *accept_inbox =
        n00b_conduit_local_accept_inbox_new(c);
    n00b_conduit_local_accept_subscribe(accept_topic, accept_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto cr = n00b_conduit_local_connect(
        c, name, .backend = N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(n00b_result_is_ok(cr));
    n00b_conduit_local_conn_t *client = n00b_result_get(cr);
    n00b_conduit_local_accept_msg_t *accepted =
        wait_for_windows_accept(accept_inbox);
    n00b_conduit_local_conn_t *server = accepted->payload.conn;

    n00b_conduit_topic_t(n00b_buffer_t *) *client_write =
        n00b_conduit_local_conn_write_topic_typed(client);
    assert(client_write != nullptr);

    n00b_conduit_topic_t(n00b_conduit_local_status_payload_t) *client_status =
        n00b_conduit_local_conn_status_topic_typed(client);
    n00b_conduit_local_status_inbox_t *status_inbox =
        n00b_conduit_local_status_inbox_new(c);
    n00b_conduit_local_status_subscribe(client_status, status_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    size_t   len     = 262144;
    uint8_t *payload = n00b_alloc_array(uint8_t, len);
    fill_pattern(payload, len);

    for (int i = 0; i < 16; i++) {
        n00b_buffer_t *buf = n00b_buffer_from_bytes((char *)payload,
                                                    (int64_t)len);
        auto wr = n00b_conduit_write(n00b_buffer_t *, client_write, buf,
                                     .sync = false);
        assert(n00b_result_is_ok(wr));
    }

    base_nanosleep_ns(100000000ULL);
    n00b_collect(arena);
    n00b_conduit_local_conn_close(client);
    n00b_collect(arena);
    n00b_conduit_local_status_msg_t *status_msg =
        wait_for_windows_status(status_inbox);
    assert(status_msg->payload.backend == N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(status_msg->payload.event == N00B_CONDUIT_LOCAL_CLOSED);
    base_nanosleep_ns(50000000ULL);
    assert(n00b_conduit_local_status_inbox_has_messages(status_inbox) == false);

    n00b_conduit_local_conn_close(server);
    n00b_conduit_local_listener_close(listener);
    n00b_conduit_destroy(c);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_local_windows_public_header_shape();
    test_local_windows_absent_endpoint();
    test_local_windows_explicit_accept();
    test_local_windows_multiple_clients();
    test_local_windows_auto_ping_pong();
    test_local_windows_ping_pong();
    test_local_windows_repeated_close();
    test_local_windows_large_message();
    test_local_windows_many_sequential_messages();
    test_local_windows_peer_disconnect_status();
    test_local_windows_pending_close_and_gc(runtime.default_arena);

    n00b_shutdown();
    return 0;
}

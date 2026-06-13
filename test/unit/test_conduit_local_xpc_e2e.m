/*
 * test_conduit_local_xpc_e2e.m - Darwin XPC local IPC e2e test.
 *
 * This test uses only the public local IPC API. The Meson target is Darwin-only;
 * the source is copied to a generated .c file so ncc, not the system
 * Objective-C frontend, compiles the public n00b headers.
 */

#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "n00b.h"
#include "conduit/local.h"
#include "conduit/rw.h"
#include "core/gc.h"
#include "core/runtime.h"

static n00b_conduit_t *
make_conduit(void)
{
    auto cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    return n00b_result_get(cr);
}

static void
test_local_xpc_public_header_shape(void)
{
    n00b_conduit_local_backend_t backend = N00B_CONDUIT_LOCAL_XPC;
    assert(backend == N00B_CONDUIT_LOCAL_XPC);

    n00b_conduit_local_peer_t peer = {
        .backend         = backend,
        .pid             = n00b_option_none(uint64_t),
        .uid             = n00b_option_none(uint64_t),
        .gid             = n00b_option_none(uint64_t),
        .code_signing_id = n00b_option_none(n00b_string_t *),
    };
    assert(peer.backend == N00B_CONDUIT_LOCAL_XPC);
    assert(n00b_option_is_set(peer.pid) == false);
    assert(n00b_option_is_set(peer.code_signing_id) == false);
}

static void
test_local_xpc_absent_endpoint(void)
{
    n00b_conduit_t *c    = make_conduit();
    n00b_string_t  *name = r"wp003-xpc-absent";

    auto cr = n00b_conduit_local_connect(c, name,
                                         .backend = N00B_CONDUIT_LOCAL_XPC);
    assert(n00b_result_is_err(cr));
    assert(n00b_result_get_err(cr) == N00B_CONDUIT_ERR_NOT_FOUND);

    n00b_conduit_destroy(c);
}

static n00b_conduit_local_accept_msg_t *
wait_for_xpc_accept(n00b_conduit_local_accept_inbox_t *inbox)
{
    for (int i = 0; i < 200; i++) {
        if (n00b_conduit_local_accept_inbox_has_messages(inbox)) {
            break;
        }
        usleep(5000);
    }

    assert(n00b_conduit_local_accept_inbox_has_messages(inbox));
    n00b_conduit_local_accept_msg_t *msg =
        n00b_conduit_local_accept_inbox_pop(inbox);
    assert(msg != nullptr);
    assert(msg->payload.conn != nullptr);
    assert(msg->payload.peer.backend == N00B_CONDUIT_LOCAL_XPC);
    if (n00b_option_is_set(msg->payload.peer.pid)) {
        assert(n00b_option_get(msg->payload.peer.pid) == (uint64_t)getpid());
    }
    assert(n00b_option_is_set(msg->payload.peer.uid));
    assert(n00b_option_is_set(msg->payload.peer.gid));
    assert(n00b_option_is_set(msg->payload.peer.code_signing_id) == false);
    return msg;
}

static void
assert_buffer_eq(n00b_buffer_t *buf, const char *expected, size_t expected_len)
{
    assert(buf != nullptr);
    assert(buf->byte_len == expected_len);
    if (expected_len != 0) {
        assert(buf->data != nullptr);
        assert(memcmp(buf->data, expected, expected_len) == 0);
    }
}

static n00b_conduit_local_status_msg_t *
wait_for_xpc_status(n00b_conduit_local_status_inbox_t *inbox)
{
    for (int i = 0; i < 200; i++) {
        if (n00b_conduit_local_status_inbox_has_messages(inbox)) {
            break;
        }
        usleep(5000);
    }

    assert(n00b_conduit_local_status_inbox_has_messages(inbox));
    n00b_conduit_local_status_msg_t *msg =
        n00b_conduit_local_status_inbox_pop(inbox);
    assert(msg != nullptr);
    return msg;
}

static n00b_conduit_message_t(n00b_buffer_t *) *
wait_for_buffer_msg(n00b_conduit_inbox_t(n00b_buffer_t *) *inbox)
{
    for (int i = 0; i < 200; i++) {
        if (n00b_conduit_inbox_has_msg(n00b_buffer_t *, inbox)) {
            break;
        }
        usleep(5000);
    }

    assert(n00b_conduit_inbox_has_msg(n00b_buffer_t *, inbox));
    n00b_conduit_message_t(n00b_buffer_t *) *msg =
        n00b_conduit_inbox_pop_msg(n00b_buffer_t *, inbox);
    assert(msg != nullptr);
    return msg;
}

static void
wait_for_buffer_count(n00b_conduit_inbox_t(n00b_buffer_t *) *inbox,
                      uint32_t expected)
{
    for (int i = 0; i < 200; i++) {
        if (n00b_conduit_inbox_msg_count(n00b_buffer_t *, inbox) >= expected) {
            return;
        }
        usleep(5000);
    }

    assert(n00b_conduit_inbox_msg_count(n00b_buffer_t *, inbox) >= expected);
}

static void
test_local_xpc_accept_explicit_and_auto(void)
{
    n00b_conduit_t *explicit_c = make_conduit();
    n00b_string_t  *explicit_name = r"wp003-xpc-explicit-accept";

    auto explicit_lr = n00b_conduit_local_listen(
        explicit_c, explicit_name, .backend = N00B_CONDUIT_LOCAL_XPC);
    assert(n00b_result_is_ok(explicit_lr));
    n00b_conduit_local_listener_t *explicit_listener =
        n00b_result_get(explicit_lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *explicit_topic =
        n00b_conduit_local_listener_accept_topic_typed(explicit_listener);
    assert(explicit_topic != nullptr);
    n00b_conduit_local_accept_inbox_t *explicit_inbox =
        n00b_conduit_local_accept_inbox_new(explicit_c);
    n00b_conduit_local_accept_subscribe(explicit_topic, explicit_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto explicit_cr = n00b_conduit_local_connect(
        explicit_c, explicit_name, .backend = N00B_CONDUIT_LOCAL_XPC);
    assert(n00b_result_is_ok(explicit_cr));
    n00b_conduit_local_conn_t *explicit_client = n00b_result_get(explicit_cr);
    n00b_conduit_local_accept_msg_t *explicit_msg =
        wait_for_xpc_accept(explicit_inbox);

    n00b_conduit_local_conn_close(explicit_msg->payload.conn);
    n00b_conduit_local_conn_close(explicit_client);
    n00b_conduit_local_listener_close(explicit_listener);
    n00b_conduit_destroy(explicit_c);

    n00b_conduit_t *auto_c = make_conduit();
    n00b_string_t  *auto_name = r"wp003-xpc-auto-accept";

    auto auto_lr = n00b_conduit_local_listen(auto_c, auto_name);
    assert(n00b_result_is_ok(auto_lr));
    n00b_conduit_local_listener_t *auto_listener = n00b_result_get(auto_lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *auto_topic =
        n00b_conduit_local_listener_accept_topic_typed(auto_listener);
    assert(auto_topic != nullptr);
    n00b_conduit_local_accept_inbox_t *auto_inbox =
        n00b_conduit_local_accept_inbox_new(auto_c);
    n00b_conduit_local_accept_subscribe(auto_topic, auto_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto auto_cr = n00b_conduit_local_connect(auto_c, auto_name);
    assert(n00b_result_is_ok(auto_cr));
    n00b_conduit_local_conn_t *auto_client = n00b_result_get(auto_cr);
    n00b_conduit_local_accept_msg_t *auto_msg = wait_for_xpc_accept(auto_inbox);

    n00b_conduit_local_conn_close(auto_msg->payload.conn);
    n00b_conduit_local_conn_close(auto_client);
    n00b_conduit_local_listener_close(auto_listener);
    n00b_conduit_destroy(auto_c);
}

static void
test_local_xpc_auto_ping_pong(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_string_t  *name = r"wp003-xpc-auto-ping-pong";

    auto lr = n00b_conduit_local_listen(c, name);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_local_listener_accept_topic_typed(listener);
    assert(accept_topic != nullptr);
    n00b_conduit_local_accept_inbox_t *accept_inbox =
        n00b_conduit_local_accept_inbox_new(c);
    n00b_conduit_local_accept_subscribe(accept_topic, accept_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto cr = n00b_conduit_local_connect(c, name);
    assert(n00b_result_is_ok(cr));
    n00b_conduit_local_conn_t *client = n00b_result_get(cr);
    n00b_conduit_local_accept_msg_t *accepted = wait_for_xpc_accept(accept_inbox);
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

    n00b_buffer_t *ping = n00b_buffer_from_bytes("auto-ping", 9);
    auto wr = n00b_conduit_write(n00b_buffer_t *, client_write, ping,
                                 .sync = false);
    assert(n00b_result_is_ok(wr));
    auto rr = n00b_conduit_read(n00b_buffer_t *, server_read,
                                .timeout_ms = 1000);
    assert(n00b_result_is_ok(rr));
    n00b_conduit_message_t(n00b_buffer_t *) *read_msg = n00b_result_get(rr);
    assert_buffer_eq(read_msg->payload, "auto-ping", 9);

    n00b_buffer_t *pong = n00b_buffer_from_bytes("auto-pong", 9);
    wr = n00b_conduit_write(n00b_buffer_t *, server_write, pong,
                            .sync = false);
    assert(n00b_result_is_ok(wr));
    rr = n00b_conduit_read(n00b_buffer_t *, client_read,
                           .timeout_ms = 1000);
    assert(n00b_result_is_ok(rr));
    read_msg = n00b_result_get(rr);
    assert_buffer_eq(read_msg->payload, "auto-pong", 9);

    n00b_conduit_local_conn_close(server);
    n00b_conduit_local_conn_close(client);
    n00b_conduit_local_listener_close(listener);
    n00b_conduit_destroy(c);
}

static void
test_local_xpc_immediate_write_before_accept_drain(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_string_t  *name = r"wp003-xpc-immediate-write";

    auto lr = n00b_conduit_local_listen(c, name,
                                        .backend = N00B_CONDUIT_LOCAL_XPC);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_local_listener_accept_topic_typed(listener);
    n00b_conduit_local_accept_inbox_t *accept_inbox =
        n00b_conduit_local_accept_inbox_new(c);
    n00b_conduit_local_accept_subscribe(accept_topic, accept_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto cr = n00b_conduit_local_connect(c, name,
                                         .backend = N00B_CONDUIT_LOCAL_XPC);
    assert(n00b_result_is_ok(cr));
    n00b_conduit_local_conn_t *client = n00b_result_get(cr);

    n00b_conduit_topic_t(n00b_buffer_t *) *client_write =
        n00b_conduit_local_conn_write_topic_typed(client);
    assert(client_write != nullptr);

    n00b_buffer_t *buf = n00b_buffer_from_bytes("early-write", 11);
    auto wr = n00b_conduit_write(n00b_buffer_t *, client_write, buf,
                                 .sync = false);
    assert(n00b_result_is_ok(wr));

    n00b_conduit_local_accept_msg_t *accepted = wait_for_xpc_accept(accept_inbox);
    n00b_conduit_local_conn_t *server = accepted->payload.conn;
    n00b_conduit_topic_t(n00b_buffer_t *) *server_read =
        n00b_conduit_local_conn_read_topic_typed(server);
    assert(server_read != nullptr);

    auto rr = n00b_conduit_read(n00b_buffer_t *, server_read,
                                .timeout_ms = 1000);
    assert(n00b_result_is_ok(rr));
    n00b_conduit_message_t(n00b_buffer_t *) *read_msg = n00b_result_get(rr);
    assert_buffer_eq(read_msg->payload, "early-write", 11);

    n00b_conduit_local_conn_close(server);
    n00b_conduit_local_conn_close(client);
    n00b_conduit_local_listener_close(listener);
    n00b_conduit_destroy(c);
}

static void
test_local_xpc_buffer_ping_pong(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_string_t  *name = r"wp003-xpc-buffer-ping-pong";

    auto lr = n00b_conduit_local_listen(c, name,
                                        .backend = N00B_CONDUIT_LOCAL_XPC);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_local_listener_accept_topic_typed(listener);
    assert(accept_topic != nullptr);
    n00b_conduit_local_accept_inbox_t *accept_inbox =
        n00b_conduit_local_accept_inbox_new(c);
    n00b_conduit_local_accept_subscribe(accept_topic, accept_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto cr = n00b_conduit_local_connect(c, name,
                                         .backend = N00B_CONDUIT_LOCAL_XPC);
    assert(n00b_result_is_ok(cr));
    n00b_conduit_local_conn_t *client = n00b_result_get(cr);
    n00b_conduit_local_accept_msg_t *accepted = wait_for_xpc_accept(accept_inbox);
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

    n00b_buffer_t *ping = n00b_buffer_from_bytes("ping-one", 8);
    auto wr = n00b_conduit_write(n00b_buffer_t *, client_write, ping,
                                 .sync = false);
    assert(n00b_result_is_ok(wr));
    auto rr = n00b_conduit_read(n00b_buffer_t *, server_read,
                                .timeout_ms = 1000);
    assert(n00b_result_is_ok(rr));
    n00b_conduit_message_t(n00b_buffer_t *) *read_msg = n00b_result_get(rr);
    assert_buffer_eq(read_msg->payload, "ping-one", 8);

    n00b_buffer_t *pong = n00b_buffer_from_bytes("pong-two", 8);
    wr = n00b_conduit_write(n00b_buffer_t *, server_write, pong,
                            .sync = false);
    assert(n00b_result_is_ok(wr));
    rr = n00b_conduit_read(n00b_buffer_t *, client_read,
                           .timeout_ms = 1000);
    assert(n00b_result_is_ok(rr));
    read_msg = n00b_result_get(rr);
    assert_buffer_eq(read_msg->payload, "pong-two", 8);

    const char *seq[] = {"alpha", "beta-2", "gamma-three"};
    size_t seq_len[] = {5, 6, 11};
    n00b_conduit_inbox_t(n00b_buffer_t *) *seq_inbox =
        n00b_alloc_with_opts(n00b_conduit_inbox_t(n00b_buffer_t *),
                             &(n00b_alloc_opts_t){.allocator = c->allocator});
    n00b_conduit_inbox_init(n00b_buffer_t *, seq_inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_sub_handle_t seq_sub = n00b_conduit_subscribe(
        n00b_buffer_t *, server_read, seq_inbox,
        .operations = N00B_CONDUIT_OP_ALL);
    assert(seq_sub != N00B_CONDUIT_INVALID_SUB_HANDLE);
    for (int i = 0; i < 3; i++) {
        n00b_buffer_t *buf = n00b_buffer_from_bytes((char *)seq[i],
                                                    (int64_t)seq_len[i]);
        wr = n00b_conduit_write(n00b_buffer_t *, client_write, buf,
                                .sync = false);
        assert(n00b_result_is_ok(wr));
    }
    for (int i = 0; i < 3; i++) {
        read_msg = wait_for_buffer_msg(seq_inbox);
        assert_buffer_eq(read_msg->payload, seq[i], seq_len[i]);
    }
    n00b_conduit_sub_cancel(seq_sub);

    n00b_conduit_local_conn_close(server);
    n00b_conduit_local_conn_close(client);
    n00b_conduit_local_listener_close(listener);
    n00b_conduit_destroy(c);
}

static void
test_local_xpc_peer_close_status(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_string_t  *name = r"wp003-xpc-peer-close-status";

    auto lr = n00b_conduit_local_listen(c, name,
                                        .backend = N00B_CONDUIT_LOCAL_XPC);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_local_listener_accept_topic_typed(listener);
    n00b_conduit_local_accept_inbox_t *accept_inbox =
        n00b_conduit_local_accept_inbox_new(c);
    n00b_conduit_local_accept_subscribe(accept_topic, accept_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto cr = n00b_conduit_local_connect(c, name,
                                         .backend = N00B_CONDUIT_LOCAL_XPC);
    assert(n00b_result_is_ok(cr));
    n00b_conduit_local_conn_t *client = n00b_result_get(cr);
    n00b_conduit_local_accept_msg_t *accepted = wait_for_xpc_accept(accept_inbox);
    n00b_conduit_local_conn_t *server = accepted->payload.conn;

    n00b_conduit_topic_t(n00b_conduit_local_status_payload_t) *server_status =
        n00b_conduit_local_conn_status_topic_typed(server);
    assert(server_status != nullptr);
    n00b_conduit_local_status_inbox_t *status_inbox =
        n00b_conduit_local_status_inbox_new(c);
    n00b_conduit_local_status_subscribe(server_status, status_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    n00b_conduit_local_conn_close(client);
    n00b_conduit_local_status_msg_t *status_msg =
        wait_for_xpc_status(status_inbox);
    assert(status_msg->payload.backend == N00B_CONDUIT_LOCAL_XPC);
    assert(status_msg->payload.event == N00B_CONDUIT_LOCAL_CLOSED);

    n00b_conduit_local_conn_close(server);
    n00b_conduit_local_listener_close(listener);
    n00b_conduit_destroy(c);
}

static void
test_local_xpc_gc_during_sustained_traffic(n00b_arena_t *arena)
{
    n00b_conduit_t *c = make_conduit();
    n00b_string_t  *name = r"wp003-xpc-gc-traffic";

    auto lr = n00b_conduit_local_listen(c, name,
                                        .backend = N00B_CONDUIT_LOCAL_XPC);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_local_listener_accept_topic_typed(listener);
    n00b_conduit_local_accept_inbox_t *accept_inbox =
        n00b_conduit_local_accept_inbox_new(c);
    n00b_conduit_local_accept_subscribe(accept_topic, accept_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto cr = n00b_conduit_local_connect(c, name,
                                         .backend = N00B_CONDUIT_LOCAL_XPC);
    assert(n00b_result_is_ok(cr));
    n00b_conduit_local_conn_t *client = n00b_result_get(cr);
    n00b_conduit_local_accept_msg_t *accepted = wait_for_xpc_accept(accept_inbox);
    n00b_conduit_local_conn_t *server = accepted->payload.conn;

    n00b_conduit_topic_t(n00b_buffer_t *) *client_write =
        n00b_conduit_local_conn_write_topic_typed(client);
    n00b_conduit_topic_t(n00b_buffer_t *) *server_read =
        n00b_conduit_local_conn_read_topic_typed(server);
    assert(client_write != nullptr && server_read != nullptr);

    n00b_conduit_inbox_t(n00b_buffer_t *) *burst_inbox =
        n00b_alloc_with_opts(n00b_conduit_inbox_t(n00b_buffer_t *),
                             &(n00b_alloc_opts_t){.allocator = c->allocator});
    n00b_conduit_inbox_init(n00b_buffer_t *, burst_inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_sub_handle_t burst_sub = n00b_conduit_subscribe(
        n00b_buffer_t *, server_read, burst_inbox,
        .operations = N00B_CONDUIT_OP_ALL);
    assert(burst_sub != N00B_CONDUIT_INVALID_SUB_HANDLE);

    for (int i = 0; i < 24; i++) {
        n00b_buffer_t *buf = n00b_buffer_from_bytes("gc-roundtrip", 12);
        auto wr = n00b_conduit_write(n00b_buffer_t *, client_write, buf,
                                     .sync = false);
        assert(n00b_result_is_ok(wr));
    }
    wait_for_buffer_count(burst_inbox, 8);
    n00b_collect(arena);
    for (int i = 0; i < 24; i++) {
        n00b_conduit_message_t(n00b_buffer_t *) *read_msg =
            wait_for_buffer_msg(burst_inbox);
        assert_buffer_eq(read_msg->payload, "gc-roundtrip", 12);
    }
    n00b_collect(arena);
    n00b_conduit_sub_cancel(burst_sub);

    n00b_conduit_local_conn_close(server);
    n00b_conduit_local_conn_close(client);
    n00b_conduit_local_listener_close(listener);
    n00b_conduit_destroy(c);
}

static void
test_local_xpc_repeated_close(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_string_t  *name = r"wp003-xpc-repeated-close";

    auto lr = n00b_conduit_local_listen(c, name,
                                        .backend = N00B_CONDUIT_LOCAL_XPC);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_local_listener_accept_topic_typed(listener);
    n00b_conduit_local_accept_inbox_t *accept_inbox =
        n00b_conduit_local_accept_inbox_new(c);
    n00b_conduit_local_accept_subscribe(accept_topic, accept_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto cr = n00b_conduit_local_connect(c, name,
                                         .backend = N00B_CONDUIT_LOCAL_XPC);
    assert(n00b_result_is_ok(cr));
    n00b_conduit_local_conn_t *client = n00b_result_get(cr);
    n00b_conduit_local_accept_msg_t *accepted = wait_for_xpc_accept(accept_inbox);
    n00b_conduit_local_conn_t *server = accepted->payload.conn;

    n00b_conduit_topic_t(n00b_conduit_local_status_payload_t) *server_status =
        n00b_conduit_local_conn_status_topic_typed(server);
    assert(server_status != nullptr);
    n00b_conduit_local_status_inbox_t *status_inbox =
        n00b_conduit_local_status_inbox_new(c);
    n00b_conduit_local_status_subscribe(server_status, status_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    n00b_conduit_local_conn_close(client);
    n00b_conduit_local_conn_close(client);

    n00b_conduit_local_status_msg_t *status_msg =
        wait_for_xpc_status(status_inbox);
    assert(status_msg->payload.backend == N00B_CONDUIT_LOCAL_XPC);
    assert(status_msg->payload.event == N00B_CONDUIT_LOCAL_CLOSED);

    usleep(50000);
    assert(n00b_conduit_local_status_inbox_has_messages(status_inbox) == false);

    n00b_conduit_local_conn_close(server);
    n00b_conduit_local_conn_close(server);
    n00b_conduit_local_listener_close(listener);
    n00b_conduit_local_listener_close(listener);
    n00b_conduit_destroy(c);
}

static void
test_local_xpc_close_with_queued_writes(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_string_t  *name = r"wp003-xpc-close-queued-writes";

    auto lr = n00b_conduit_local_listen(c, name,
                                        .backend = N00B_CONDUIT_LOCAL_XPC);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_local_listener_accept_topic_typed(listener);
    n00b_conduit_local_accept_inbox_t *accept_inbox =
        n00b_conduit_local_accept_inbox_new(c);
    n00b_conduit_local_accept_subscribe(accept_topic, accept_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto cr = n00b_conduit_local_connect(c, name,
                                         .backend = N00B_CONDUIT_LOCAL_XPC);
    assert(n00b_result_is_ok(cr));
    n00b_conduit_local_conn_t *client = n00b_result_get(cr);
    n00b_conduit_local_accept_msg_t *accepted = wait_for_xpc_accept(accept_inbox);
    n00b_conduit_local_conn_t *server = accepted->payload.conn;

    n00b_conduit_topic_t(n00b_buffer_t *) *client_write =
        n00b_conduit_local_conn_write_topic_typed(client);
    n00b_conduit_topic_t(n00b_conduit_local_status_payload_t) *server_status =
        n00b_conduit_local_conn_status_topic_typed(server);
    assert(client_write != nullptr && server_status != nullptr);

    n00b_conduit_local_status_inbox_t *status_inbox =
        n00b_conduit_local_status_inbox_new(c);
    n00b_conduit_local_status_subscribe(server_status, status_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    for (int i = 0; i < 64; i++) {
        n00b_buffer_t *buf = n00b_buffer_from_bytes("queued-close", 12);
        auto wr = n00b_conduit_write(n00b_buffer_t *, client_write, buf,
                                     .sync = false);
        assert(n00b_result_is_ok(wr));
    }

    n00b_conduit_local_conn_close(client);
    n00b_conduit_local_status_msg_t *status_msg =
        wait_for_xpc_status(status_inbox);
    assert(status_msg->payload.backend == N00B_CONDUIT_LOCAL_XPC);
    assert(status_msg->payload.event == N00B_CONDUIT_LOCAL_CLOSED);

    usleep(50000);
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

    test_local_xpc_public_header_shape();
    test_local_xpc_absent_endpoint();
    test_local_xpc_accept_explicit_and_auto();
    test_local_xpc_auto_ping_pong();
    test_local_xpc_immediate_write_before_accept_drain();
    test_local_xpc_buffer_ping_pong();
    test_local_xpc_peer_close_status();
    test_local_xpc_gc_during_sustained_traffic(runtime.default_arena);
    test_local_xpc_repeated_close();
    test_local_xpc_close_with_queued_writes();

    n00b_shutdown();
    return 0;
}

/*
 * test_conduit_local_unix_e2e.c — portable local IPC over AF_UNIX.
 *
 * The test uses the public local IPC API and generic conduit read/write
 * surface. It must not consume socket accept payloads or raw fds directly.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/local.h"
#include "conduit/rw.h"
#include "conduit/service.h"
#include "core/atomic.h"
#include "core/file.h"
#include "core/runtime.h"
#include "text/strings/fmt_numbers.h"
#include "util/path.h"

static n00b_conduit_t *
make_conduit(void)
{
    auto cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    return n00b_result_get(cr);
}

static n00b_conduit_io_backend_t *
make_io_via_service(n00b_conduit_t *c)
{
    auto sr = n00b_conduit_service_new(c);
    assert(n00b_result_is_ok(sr));
    n00b_conduit_service_t *svc = n00b_result_get(sr);
    auto start_r = n00b_conduit_service_start(svc);
    assert(n00b_result_is_ok(start_r));

    int n = n00b_atomic_load(&svc->num_threads);
    for (int i = 0; i < n; i++) {
        n00b_conduit_svc_thread_t *t = svc->threads[i];
        if (t && t->role == N00B_CONDUIT_SVC_IO && t->io) {
            return t->io;
        }
    }
    assert(!"service did not spawn an IO thread");
    return nullptr;
}

static n00b_string_t *
build_tmp_path(const char *tag)
{
    char raw_prefix[128];
    int  written = snprintf(raw_prefix, sizeof(raw_prefix),
                            "libn00b-local-%s-", tag);
    assert(written > 0 && written < (int)sizeof(raw_prefix));

    n00b_string_t *prefix = n00b_string_from_cstr(raw_prefix);
    n00b_string_t *suffix = n00b_string_from_cstr(".sock");
    n00b_string_t *path   = n00b_new_temp_path(prefix, suffix);
    (void)n00b_file_unlink(path, .ignore_missing = true);
    return path;
}

static void
teardown_conduit(n00b_conduit_t *c)
{
    if (c == nullptr) {
        return;
    }

    n00b_conduit_service_t *svc = c->service;
    if (svc != nullptr) {
        n00b_conduit_service_stop(svc);
        n00b_conduit_service_destroy(svc);
    }
    n00b_conduit_destroy(c);
}

static n00b_conduit_topic_base_t *
expect_topic(n00b_option_t(n00b_conduit_topic_base_t *) topic)
{
    assert(n00b_option_is_set(topic));
    n00b_conduit_topic_base_t *base = n00b_option_get(topic);
    assert(base != nullptr);
    return base;
}

static n00b_conduit_local_conn_t *
wait_for_accept(n00b_conduit_local_accept_inbox_t *inbox)
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
    assert(msg->payload.peer.backend == N00B_CONDUIT_LOCAL_UNIX);
    return msg->payload.conn;
}

static int
count_status_event(n00b_conduit_local_status_inbox_t *inbox,
                   n00b_conduit_local_event_t         event)
{
    int count = 0;

    for (int i = 0; i < 20; i++) {
        while (n00b_conduit_local_status_inbox_has_messages(inbox)) {
            n00b_conduit_local_status_msg_t *msg =
                n00b_conduit_local_status_inbox_pop(inbox);
            assert(msg != nullptr);
            assert(msg->payload.backend == N00B_CONDUIT_LOCAL_UNIX);
            if (msg->payload.event == event) {
                count++;
            }
        }
        usleep(1000);
    }

    return count;
}

static void
assert_read_buffer(n00b_conduit_local_conn_t *conn, const char *expected)
{
    n00b_conduit_topic_t(n00b_buffer_t *) *read_topic =
        n00b_conduit_local_conn_read_topic_typed(conn);
    assert(read_topic != nullptr);

    auto rr = n00b_conduit_read(n00b_buffer_t *, read_topic, .timeout_ms = 2000);
    assert(n00b_result_is_ok(rr));
    n00b_conduit_message_t(n00b_buffer_t *) *msg = n00b_result_get(rr);
    assert(msg != nullptr);
    assert(msg->payload != nullptr);

    size_t len = strlen(expected);
    assert(msg->payload->byte_len == len);
    assert(memcmp(msg->payload->data, expected, len) == 0);
}

static void
write_buffer(n00b_conduit_local_conn_t *conn, const char *payload)
{
    n00b_conduit_topic_t(n00b_buffer_t *) *write_topic =
        n00b_conduit_local_conn_write_topic_typed(conn);
    assert(write_topic != nullptr);

    n00b_buffer_t *buf = n00b_buffer_from_cstr(payload);
    auto wr = n00b_conduit_write(n00b_buffer_t *, write_topic, buf,
                                 .timeout_ms = 2000);
    assert(n00b_result_is_ok(wr));
}

static void
test_local_unix_ping_pong_and_close(void)
{
    n00b_conduit_t            *c    = make_conduit();
    n00b_conduit_io_backend_t *io   = make_io_via_service(c);
    n00b_string_t             *path = build_tmp_path("ping-pong");

    auto lr = n00b_conduit_local_listen(c, path,
                                        .backend      = N00B_CONDUIT_LOCAL_UNIX,
                                        .io           = io,
                                        .unlink_stale = true);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_local_listener_accept_topic_typed(listener);
    assert(accept_topic != nullptr);

    n00b_conduit_local_accept_inbox_t *accept_inbox =
        n00b_conduit_local_accept_inbox_new(c);
    n00b_conduit_local_accept_subscribe(accept_topic, accept_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto cr = n00b_conduit_local_connect(c, path,
                                         .backend = N00B_CONDUIT_LOCAL_UNIX,
                                         .io      = io);
    assert(n00b_result_is_ok(cr));
    n00b_conduit_local_conn_t *client = n00b_result_get(cr);
    n00b_conduit_local_conn_t *server = wait_for_accept(accept_inbox);

    n00b_conduit_topic_base_t *client_read =
        expect_topic(n00b_conduit_local_conn_read_topic(client));
    n00b_conduit_topic_base_t *client_write =
        expect_topic(n00b_conduit_local_conn_write_topic(client));
    n00b_conduit_topic_base_t *client_status =
        expect_topic(n00b_conduit_local_conn_status_topic(client));
    n00b_conduit_topic_base_t *server_read =
        expect_topic(n00b_conduit_local_conn_read_topic(server));
    n00b_conduit_topic_base_t *server_write =
        expect_topic(n00b_conduit_local_conn_write_topic(server));
    n00b_conduit_topic_base_t *server_status =
        expect_topic(n00b_conduit_local_conn_status_topic(server));
    n00b_conduit_topic_base_t *listener_accept =
        expect_topic(n00b_conduit_local_listener_accept_topic(listener));

    n00b_conduit_topic_t(n00b_conduit_local_status_payload_t) *client_status_topic =
        n00b_conduit_local_conn_status_topic_typed(client);
    n00b_conduit_topic_t(n00b_conduit_local_status_payload_t) *server_status_topic =
        n00b_conduit_local_conn_status_topic_typed(server);
    assert(client_status_topic != nullptr);
    assert(server_status_topic != nullptr);

    n00b_conduit_local_status_inbox_t *client_status_inbox =
        n00b_conduit_local_status_inbox_new(c);
    n00b_conduit_local_status_inbox_t *server_status_inbox =
        n00b_conduit_local_status_inbox_new(c);
    n00b_conduit_local_status_subscribe(client_status_topic,
                                        client_status_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);
    n00b_conduit_local_status_subscribe(server_status_topic,
                                        server_status_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    write_buffer(client, "client-to-server");
    assert_read_buffer(server, "client-to-server");

    write_buffer(server, "server-to-client");
    assert_read_buffer(client, "server-to-client");

    uint64_t client_read_gen     = n00b_conduit_topic_generation(client_read);
    uint64_t client_write_gen    = n00b_conduit_topic_generation(client_write);
    uint64_t client_status_gen   = n00b_conduit_topic_generation(client_status);
    uint64_t server_read_gen     = n00b_conduit_topic_generation(server_read);
    uint64_t server_write_gen    = n00b_conduit_topic_generation(server_write);
    uint64_t server_status_gen   = n00b_conduit_topic_generation(server_status);
    uint64_t listener_accept_gen = n00b_conduit_topic_generation(listener_accept);

    n00b_conduit_local_conn_close(client);
    n00b_conduit_local_conn_close(client);
    n00b_conduit_local_conn_close(server);
    n00b_conduit_local_conn_close(server);
    n00b_conduit_local_listener_close(listener);
    n00b_conduit_local_listener_close(listener);

    assert(count_status_event(client_status_inbox,
                              N00B_CONDUIT_LOCAL_CLOSED) == 1);
    assert(count_status_event(server_status_inbox,
                              N00B_CONDUIT_LOCAL_CLOSED) == 1);

    assert(n00b_conduit_topic_generation(client_read) == client_read_gen + 1);
    assert(n00b_conduit_topic_generation(client_write) == client_write_gen + 1);
    assert(n00b_conduit_topic_generation(client_status) == client_status_gen + 1);
    assert(n00b_conduit_topic_generation(server_read) == server_read_gen + 1);
    assert(n00b_conduit_topic_generation(server_write) == server_write_gen + 1);
    assert(n00b_conduit_topic_generation(server_status) == server_status_gen + 1);
    assert(n00b_conduit_topic_generation(listener_accept) == listener_accept_gen + 1);

    assert(n00b_option_is_set(n00b_conduit_local_conn_read_topic(client)) == false);
    assert(n00b_option_is_set(n00b_conduit_local_conn_write_topic(client)) == false);
    assert(n00b_option_is_set(n00b_conduit_local_conn_status_topic(client)) == false);
    assert(n00b_option_is_set(n00b_conduit_local_conn_read_topic(server)) == false);
    assert(n00b_option_is_set(n00b_conduit_local_conn_write_topic(server)) == false);
    assert(n00b_option_is_set(n00b_conduit_local_conn_status_topic(server)) == false);
    assert(n00b_option_is_set(
               n00b_conduit_local_listener_accept_topic(listener)) == false);
    assert(n00b_conduit_local_conn_read_topic_typed(client) == nullptr);
    assert(n00b_conduit_local_conn_write_topic_typed(client) == nullptr);
    assert(n00b_conduit_local_conn_status_topic_typed(client) == nullptr);
    assert(n00b_conduit_local_listener_accept_topic_typed(listener) == nullptr);

    (void)n00b_file_unlink(path, .ignore_missing = true);

    teardown_conduit(c);
}

static void
test_local_unix_multiple_clients(void)
{
    n00b_conduit_t            *c    = make_conduit();
    n00b_conduit_io_backend_t *io   = make_io_via_service(c);
    n00b_string_t             *path = build_tmp_path("multi");

    auto lr = n00b_conduit_local_listen(c, path,
                                        .backend      = N00B_CONDUIT_LOCAL_UNIX,
                                        .io           = io,
                                        .unlink_stale = true);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_local_listener_accept_topic_typed(listener);
    assert(accept_topic != nullptr);

    n00b_conduit_local_accept_inbox_t *accept_inbox =
        n00b_conduit_local_accept_inbox_new(c);
    n00b_conduit_local_accept_subscribe(accept_topic, accept_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto cr1 = n00b_conduit_local_connect(c, path,
                                          .backend = N00B_CONDUIT_LOCAL_UNIX,
                                          .io      = io);
    assert(n00b_result_is_ok(cr1));
    n00b_conduit_local_conn_t *client1 = n00b_result_get(cr1);
    n00b_conduit_local_conn_t *server1 = wait_for_accept(accept_inbox);

    auto cr2 = n00b_conduit_local_connect(c, path,
                                          .backend = N00B_CONDUIT_LOCAL_UNIX,
                                          .io      = io);
    assert(n00b_result_is_ok(cr2));
    n00b_conduit_local_conn_t *client2 = n00b_result_get(cr2);
    n00b_conduit_local_conn_t *server2 = wait_for_accept(accept_inbox);

    assert(client1 != client2);
    assert(server1 != server2);

    n00b_conduit_topic_base_t *server1_read =
        expect_topic(n00b_conduit_local_conn_read_topic(server1));
    n00b_conduit_topic_base_t *server2_read =
        expect_topic(n00b_conduit_local_conn_read_topic(server2));
    assert(server1_read != server2_read);

    write_buffer(client1, "client-one");
    write_buffer(client2, "client-two");
    assert_read_buffer(server1, "client-one");
    assert_read_buffer(server2, "client-two");

    n00b_conduit_local_conn_close(client1);
    n00b_conduit_local_conn_close(client2);
    n00b_conduit_local_conn_close(server1);
    n00b_conduit_local_conn_close(server2);
    n00b_conduit_local_listener_close(listener);

    (void)n00b_file_unlink(path, .ignore_missing = true);
    teardown_conduit(c);
}

static void
test_local_auto_backend_behavior(void)
{
    n00b_conduit_t *c    = make_conduit();
    n00b_string_t  *path = build_tmp_path("auto");

#ifdef __APPLE__
    auto lr = n00b_conduit_local_listen(c, path);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);

    auto cr = n00b_conduit_local_connect(c, path);
    assert(n00b_result_is_ok(cr));
    n00b_conduit_local_conn_t *client = n00b_result_get(cr);

    n00b_conduit_local_conn_close(client);
    n00b_conduit_local_listener_close(listener);
#else
    n00b_conduit_io_backend_t *io = make_io_via_service(c);
    auto lr = n00b_conduit_local_listen(c, path,
                                        .io           = io,
                                        .unlink_stale = true);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_local_listener_accept_topic_typed(listener);
    assert(accept_topic != nullptr);

    n00b_conduit_local_accept_inbox_t *accept_inbox =
        n00b_conduit_local_accept_inbox_new(c);
    n00b_conduit_local_accept_subscribe(accept_topic, accept_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto cr = n00b_conduit_local_connect(c, path, .io = io);
    assert(n00b_result_is_ok(cr));
    n00b_conduit_local_conn_t *client = n00b_result_get(cr);
    n00b_conduit_local_conn_t *server = wait_for_accept(accept_inbox);

    write_buffer(client, "auto-client-to-server");
    assert_read_buffer(server, "auto-client-to-server");

    n00b_conduit_local_conn_close(client);
    n00b_conduit_local_conn_close(server);
    n00b_conduit_local_listener_close(listener);
#endif

    (void)n00b_file_unlink(path, .ignore_missing = true);
    teardown_conduit(c);
}

static void
test_local_unsupported_backend_is_structured(void)
{
    n00b_conduit_t *c    = make_conduit();
    n00b_string_t  *path = build_tmp_path("unsupported");

    auto lr = n00b_conduit_local_listen(c, path,
                                        .backend = N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(n00b_result_is_err(lr));
    assert(n00b_result_get_err(lr) == N00B_CONDUIT_ERR_NOT_SUPPORTED);

    auto cr = n00b_conduit_local_connect(c, path,
                                         .backend = N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
    assert(n00b_result_is_err(cr));
    assert(n00b_result_get_err(cr) == N00B_CONDUIT_ERR_NOT_SUPPORTED);

    teardown_conduit(c);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_local_unsupported_backend_is_structured();
    test_local_auto_backend_behavior();
    test_local_unix_multiple_clients();
    test_local_unix_ping_pong_and_close();

    n00b_shutdown();
    return 0;
}

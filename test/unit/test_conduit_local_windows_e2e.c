/*
 * test_conduit_local_windows_e2e.c - Windows named local IPC e2e test.
 *
 * This target is Windows-only and uses only the public portable local IPC API.
 * Phase 2 covers named listener/connect/accept lifecycle; data-path exchange
 * and terminal status mapping are intentionally left for WP-004 Phase 3.
 */

#include <assert.h>

#include "n00b.h"
#include "conduit/local.h"
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

    n00b_conduit_local_conn_close(accepted1->payload.conn);
    n00b_conduit_local_conn_close(accepted2->payload.conn);
    n00b_conduit_local_conn_close(client1);
    n00b_conduit_local_conn_close(client2);
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

    n00b_shutdown();
    return 0;
}

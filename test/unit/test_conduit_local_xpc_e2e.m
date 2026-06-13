/*
 * test_conduit_local_xpc_e2e.m - Darwin XPC local IPC e2e test.
 *
 * This test uses only the public local IPC API. The Meson target is Darwin-only;
 * the source is copied to a generated .c file so ncc, not the system
 * Objective-C frontend, compiles the public n00b headers.
 */

#include <assert.h>
#include <unistd.h>

#include "n00b.h"
#include "conduit/local.h"
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

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_local_xpc_public_header_shape();
    test_local_xpc_absent_endpoint();
    test_local_xpc_accept_explicit_and_auto();

    n00b_shutdown();
    return 0;
}

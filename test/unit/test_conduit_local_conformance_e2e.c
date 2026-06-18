/*
 * test_conduit_local_conformance_e2e.c - portable local IPC conformance.
 *
 * This harness intentionally exercises the public local IPC surface only:
 * listen/connect, local topics/inboxes, and generic conduit read/write.
 */

#include <assert.h>

#include "n00b.h"
#include "conduit/local.h"
#include "conduit/rw.h"
#include "conduit/service.h"
#include "core/file.h"
#include "core/platform.h"
#include "core/runtime.h"
#include "util/path.h"

typedef enum {
    LOCAL_CONF_AUTO,
    LOCAL_CONF_EXPLICIT_XPC,
    LOCAL_CONF_EXPLICIT_UNIX,
    LOCAL_CONF_EXPLICIT_WINDOWS,
} local_conf_case_id_t;

typedef struct {
    local_conf_case_id_t        id;
    n00b_conduit_local_backend_t selector;
    n00b_conduit_local_backend_t expected;
    bool                         uses_path;
    bool                         needs_service;
} local_conf_case_t;

#define LOCAL_CONF_LITERAL_LEN(s) ((int64_t)(sizeof(s) - 1))

typedef struct {
    n00b_conduit_local_conn_t *client;
    n00b_conduit_local_conn_t *server;
} local_conf_conn_pair_t;

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

    auto svc_thread_opt = n00b_conduit_service_default_io(svc);
    assert(n00b_option_is_set(svc_thread_opt));

    auto io_opt = n00b_conduit_svc_thread_io(n00b_option_get(svc_thread_opt));
    assert(n00b_option_is_set(io_opt));
    return n00b_option_get(io_opt);
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

static n00b_string_t *
build_tmp_path(void)
{
    n00b_string_t *path = n00b_new_temp_path(r"libn00b-local-conf-",
                                             r".sock");
    (void)n00b_file_unlink(path, .ignore_missing = true);
    return path;
}

static n00b_string_t *
case_name(local_conf_case_id_t id)
{
    switch (id) {
    case LOCAL_CONF_AUTO:
#if defined(_WIN32)
        return r"wp005-conformance-auto-windows";
#elif defined(__APPLE__)
        return r"wp005-conformance-auto-xpc";
#else
        return build_tmp_path();
#endif
    case LOCAL_CONF_EXPLICIT_XPC:
        return r"wp005-conformance-explicit-xpc";
    case LOCAL_CONF_EXPLICIT_UNIX:
        return build_tmp_path();
    case LOCAL_CONF_EXPLICIT_WINDOWS:
        return r"wp005-conformance-explicit-windows";
    }

    assert(!"unknown local conformance case");
    return nullptr;
}

static n00b_string_t *
multi_case_name(local_conf_case_id_t id)
{
    switch (id) {
    case LOCAL_CONF_AUTO:
#if defined(_WIN32)
        return r"wp005-conformance-multi-auto-windows";
#elif defined(__APPLE__)
        return r"wp005-conformance-multi-auto-xpc";
#else
        return build_tmp_path();
#endif
    case LOCAL_CONF_EXPLICIT_XPC:
        return r"wp005-conformance-multi-explicit-xpc";
    case LOCAL_CONF_EXPLICIT_UNIX:
        return build_tmp_path();
    case LOCAL_CONF_EXPLICIT_WINDOWS:
        return r"wp005-conformance-multi-explicit-windows";
    }

    assert(!"unknown local conformance case");
    return nullptr;
}

static n00b_string_t *
dead_endpoint_name(local_conf_case_id_t id)
{
    switch (id) {
    case LOCAL_CONF_AUTO:
#if defined(_WIN32)
        return r"wp005-conformance-dead-auto-windows";
#elif defined(__APPLE__)
        return r"wp005-conformance-dead-auto-xpc";
#else
        return build_tmp_path();
#endif
    case LOCAL_CONF_EXPLICIT_XPC:
        return r"wp005-conformance-dead-explicit-xpc";
    case LOCAL_CONF_EXPLICIT_UNIX:
        return build_tmp_path();
    case LOCAL_CONF_EXPLICIT_WINDOWS:
        return r"wp005-conformance-dead-explicit-windows";
    }

    assert(!"unknown local conformance case");
    return nullptr;
}

static void
assert_bytes_eq(n00b_buffer_t *buf, const char *expected, int64_t len)
{
    assert(buf != nullptr);
    assert(buf->byte_len == (uint64_t)len);
    for (int64_t i = 0; i < len; i++) {
        assert(buf->data[i] == (uint8_t)expected[i]);
    }
}

static void
write_buffer(n00b_conduit_local_conn_t *conn,
             const char                *bytes,
             int64_t                    len)
{
    n00b_conduit_topic_t(n00b_buffer_t *) *write_topic =
        n00b_conduit_local_conn_write_topic_typed(conn);
    assert(write_topic != nullptr);

    n00b_buffer_t *buf = n00b_buffer_from_bytes((char *)bytes, len);
    auto wr = n00b_conduit_write(n00b_buffer_t *, write_topic, buf,
                                 .sync = false,
                                 .timeout_ms = 4000);
    assert(n00b_result_is_ok(wr));
}

static void
assert_read_buffer(n00b_conduit_local_conn_t *conn,
                   const char                *expected,
                   int64_t                    len)
{
    n00b_conduit_topic_t(n00b_buffer_t *) *read_topic =
        n00b_conduit_local_conn_read_topic_typed(conn);
    assert(read_topic != nullptr);

    auto rr = n00b_conduit_read(n00b_buffer_t *, read_topic,
                                .timeout_ms = 4000);
    assert(n00b_result_is_ok(rr));

    n00b_conduit_message_t(n00b_buffer_t *) *msg = n00b_result_get(rr);
    assert(msg != nullptr);
    assert_bytes_eq(msg->payload, expected, len);
}

static void
assert_sequential_messages(n00b_conduit_local_conn_t *writer,
                           n00b_conduit_local_conn_t *reader)
{
    const char *seq[] = {
        "wp005-seq-one",
        "wp005-seq-two",
        "wp005-seq-three",
    };
    int64_t seq_len[] = {
        LOCAL_CONF_LITERAL_LEN("wp005-seq-one"),
        LOCAL_CONF_LITERAL_LEN("wp005-seq-two"),
        LOCAL_CONF_LITERAL_LEN("wp005-seq-three"),
    };

    for (int i = 0; i < 3; i++) {
        write_buffer(writer, seq[i], seq_len[i]);
        assert_read_buffer(reader, seq[i], seq_len[i]);
    }
}

static void
assert_peer_facts(n00b_conduit_local_peer_t      *peer,
                  n00b_conduit_local_backend_t    expected)
{
    assert(peer != nullptr);
    assert(peer->backend == expected);
    assert(n00b_option_is_set(peer->code_signing_id) == false);

    if (expected == N00B_CONDUIT_LOCAL_WINDOWS_NAMED) {
        assert(n00b_option_is_set(peer->uid) == false);
        assert(n00b_option_is_set(peer->gid) == false);
    }
}

static n00b_conduit_local_conn_t *
wait_for_accept(n00b_conduit_local_accept_inbox_t *inbox,
                n00b_conduit_local_backend_t       expected)
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
    assert_peer_facts(&msg->payload.peer, expected);
    return msg->payload.conn;
}

static int
count_status_event(n00b_conduit_local_status_inbox_t *inbox,
                   n00b_conduit_local_backend_t       expected_backend,
                   n00b_conduit_local_event_t         expected_event)
{
    int count = 0;

    for (int i = 0; i < 400; i++) {
        while (n00b_conduit_local_status_inbox_has_messages(inbox)) {
            n00b_conduit_local_status_msg_t *msg =
                n00b_conduit_local_status_inbox_pop(inbox);
            assert(msg != nullptr);
            assert(msg->payload.backend == expected_backend);
            if (msg->payload.event == expected_event) {
                count++;
            }
        }
        base_nanosleep_ns(5000000ULL);
    }

    return count;
}

static void
run_supported_case(local_conf_case_t tc)
{
    n00b_conduit_t            *c    = make_conduit();
    n00b_conduit_io_backend_t *io   = nullptr;
    n00b_string_t             *name = case_name(tc.id);

    if (tc.needs_service) {
        io = make_io_via_service(c);
    }

    auto lr = n00b_conduit_local_listen(c, name,
                                        .backend      = tc.selector,
                                        .io           = io,
                                        .unlink_stale = tc.uses_path);
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
                                         .backend = tc.selector,
                                         .io      = io);
    assert(n00b_result_is_ok(cr));
    n00b_conduit_local_conn_t *client = n00b_result_get(cr);
    n00b_conduit_local_conn_t *server = wait_for_accept(accept_inbox,
                                                        tc.expected);

    n00b_conduit_topic_t(n00b_conduit_local_status_payload_t) *server_status =
        n00b_conduit_local_conn_status_topic_typed(server);
    assert(server_status != nullptr);
    n00b_conduit_local_status_inbox_t *status_inbox =
        n00b_conduit_local_status_inbox_new(c);
    n00b_conduit_local_status_subscribe(server_status, status_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    write_buffer(client, "wp005-client-to-server",
                 LOCAL_CONF_LITERAL_LEN("wp005-client-to-server"));
    assert_read_buffer(server, "wp005-client-to-server",
                       LOCAL_CONF_LITERAL_LEN("wp005-client-to-server"));
    write_buffer(server, "wp005-server-to-client",
                 LOCAL_CONF_LITERAL_LEN("wp005-server-to-client"));
    assert_read_buffer(client, "wp005-server-to-client",
                       LOCAL_CONF_LITERAL_LEN("wp005-server-to-client"));

    assert_sequential_messages(client, server);

    n00b_conduit_local_conn_close(client);
    n00b_conduit_local_conn_close(client);
    n00b_conduit_local_conn_close(server);
    n00b_conduit_local_conn_close(server);

    assert(count_status_event(status_inbox, tc.expected,
                              N00B_CONDUIT_LOCAL_CLOSED) == 1);

    n00b_conduit_local_listener_close(listener);
    n00b_conduit_local_listener_close(listener);

    assert(n00b_conduit_local_conn_read_topic_typed(client) == nullptr);
    assert(n00b_conduit_local_conn_write_topic_typed(client) == nullptr);
    assert(n00b_conduit_local_conn_status_topic_typed(client) == nullptr);
    assert(n00b_conduit_local_conn_read_topic_typed(server) == nullptr);
    assert(n00b_conduit_local_conn_write_topic_typed(server) == nullptr);
    assert(n00b_conduit_local_conn_status_topic_typed(server) == nullptr);
    assert(n00b_conduit_local_listener_accept_topic_typed(listener) == nullptr);

    if (tc.uses_path) {
        (void)n00b_file_unlink(name, .ignore_missing = true);
    }
    teardown_conduit(c);
}

static local_conf_conn_pair_t
connect_pair(n00b_conduit_t                   *c,
             n00b_string_t                    *name,
             local_conf_case_t                 tc,
             n00b_conduit_io_backend_t        *io,
             n00b_conduit_local_accept_inbox_t *accept_inbox)
{
    auto cr = n00b_conduit_local_connect(c, name,
                                         .backend = tc.selector,
                                         .io      = io);
    assert(n00b_result_is_ok(cr));

    local_conf_conn_pair_t pair = {
        .client = n00b_result_get(cr),
        .server = wait_for_accept(accept_inbox, tc.expected),
    };
    return pair;
}

static void
run_multi_client_case(local_conf_case_t tc)
{
    n00b_conduit_t            *c    = make_conduit();
    n00b_conduit_io_backend_t *io   = nullptr;
    n00b_string_t             *name = multi_case_name(tc.id);

    if (tc.needs_service) {
        io = make_io_via_service(c);
    }

    auto lr = n00b_conduit_local_listen(c, name,
                                        .backend      = tc.selector,
                                        .io           = io,
                                        .unlink_stale = tc.uses_path);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_local_listener_accept_topic_typed(listener);
    assert(accept_topic != nullptr);
    n00b_conduit_local_accept_inbox_t *accept_inbox =
        n00b_conduit_local_accept_inbox_new(c);
    n00b_conduit_local_accept_subscribe(accept_topic, accept_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    local_conf_conn_pair_t first = connect_pair(c, name, tc, io, accept_inbox);
    local_conf_conn_pair_t second = connect_pair(c, name, tc, io, accept_inbox);

    assert(first.client != second.client);
    assert(first.server != second.server);
    assert(n00b_conduit_local_conn_read_topic_typed(first.server) !=
           n00b_conduit_local_conn_read_topic_typed(second.server));

    write_buffer(first.client, "wp005-multi-client-one",
                 LOCAL_CONF_LITERAL_LEN("wp005-multi-client-one"));
    write_buffer(second.client, "wp005-multi-client-two",
                 LOCAL_CONF_LITERAL_LEN("wp005-multi-client-two"));
    assert_read_buffer(first.server, "wp005-multi-client-one",
                       LOCAL_CONF_LITERAL_LEN("wp005-multi-client-one"));
    assert_read_buffer(second.server, "wp005-multi-client-two",
                       LOCAL_CONF_LITERAL_LEN("wp005-multi-client-two"));

    write_buffer(first.server, "wp005-multi-server-one",
                 LOCAL_CONF_LITERAL_LEN("wp005-multi-server-one"));
    write_buffer(second.server, "wp005-multi-server-two",
                 LOCAL_CONF_LITERAL_LEN("wp005-multi-server-two"));
    assert_read_buffer(first.client, "wp005-multi-server-one",
                       LOCAL_CONF_LITERAL_LEN("wp005-multi-server-one"));
    assert_read_buffer(second.client, "wp005-multi-server-two",
                       LOCAL_CONF_LITERAL_LEN("wp005-multi-server-two"));

    n00b_conduit_local_conn_close(first.client);
    n00b_conduit_local_conn_close(second.client);
    n00b_conduit_local_conn_close(first.server);
    n00b_conduit_local_conn_close(second.server);
    n00b_conduit_local_listener_close(listener);

    if (tc.uses_path) {
        (void)n00b_file_unlink(name, .ignore_missing = true);
    }
    teardown_conduit(c);
}

static void
run_dead_endpoint_case(local_conf_case_t tc)
{
    n00b_conduit_t            *c    = make_conduit();
    n00b_conduit_io_backend_t *io   = nullptr;
    n00b_string_t             *name = dead_endpoint_name(tc.id);

    if (tc.needs_service) {
        io = make_io_via_service(c);
    }
    if (tc.uses_path) {
        (void)n00b_file_unlink(name, .ignore_missing = true);
    }

    auto cr = n00b_conduit_local_connect(c, name,
                                         .backend = tc.selector,
                                         .io      = io);
    assert(n00b_result_is_err(cr));
    assert(n00b_result_get_err(cr) == N00B_CONDUIT_ERR_NOT_FOUND);

    if (tc.uses_path) {
        (void)n00b_file_unlink(name, .ignore_missing = true);
    }
    teardown_conduit(c);
}

static void
run_stale_unix_endpoint_case(local_conf_case_t tc)
{
    if (tc.uses_path == false) {
        return;
    }

    n00b_conduit_t            *c    = make_conduit();
    n00b_conduit_io_backend_t *io   = nullptr;
    n00b_string_t             *name = dead_endpoint_name(tc.id);

    if (tc.needs_service) {
        io = make_io_via_service(c);
    }

    auto lr = n00b_conduit_local_listen(c, name,
                                        .backend      = tc.selector,
                                        .io           = io,
                                        .unlink_stale = true);
    assert(n00b_result_is_ok(lr));

    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);
    n00b_conduit_local_listener_close(listener);

    auto cr = n00b_conduit_local_connect(c, name,
                                         .backend = tc.selector,
                                         .io      = io);
    assert(n00b_result_is_err(cr));
    assert(n00b_result_get_err(cr) == N00B_CONDUIT_ERR_NOT_FOUND);

    (void)n00b_file_unlink(name, .ignore_missing = true);
    teardown_conduit(c);
}

static void
assert_unsupported_backend(n00b_conduit_local_backend_t backend)
{
    n00b_conduit_t *c = make_conduit();
    n00b_string_t  *name = r"wp005-conformance-unsupported";

    auto lr = n00b_conduit_local_listen(c, name, .backend = backend);
    assert(n00b_result_is_err(lr));
    assert(n00b_result_get_err(lr) == N00B_CONDUIT_ERR_NOT_SUPPORTED);

    auto cr = n00b_conduit_local_connect(c, name, .backend = backend);
    assert(n00b_result_is_err(cr));
    assert(n00b_result_get_err(cr) == N00B_CONDUIT_ERR_NOT_SUPPORTED);

    teardown_conduit(c);
}

static void
test_supported_backend_matrix(void)
{
#if defined(_WIN32)
    local_conf_case_t cases[] = {
        {LOCAL_CONF_AUTO,
         N00B_CONDUIT_LOCAL_AUTO,
         N00B_CONDUIT_LOCAL_WINDOWS_NAMED,
         false,
         false},
        {LOCAL_CONF_EXPLICIT_WINDOWS,
         N00B_CONDUIT_LOCAL_WINDOWS_NAMED,
         N00B_CONDUIT_LOCAL_WINDOWS_NAMED,
         false,
         false},
    };
#elif defined(__APPLE__)
    local_conf_case_t cases[] = {
        {LOCAL_CONF_AUTO,
         N00B_CONDUIT_LOCAL_AUTO,
         N00B_CONDUIT_LOCAL_XPC,
         false,
         false},
        {LOCAL_CONF_EXPLICIT_XPC,
         N00B_CONDUIT_LOCAL_XPC,
         N00B_CONDUIT_LOCAL_XPC,
         false,
         false},
        {LOCAL_CONF_EXPLICIT_UNIX,
         N00B_CONDUIT_LOCAL_UNIX,
         N00B_CONDUIT_LOCAL_UNIX,
         true,
         true},
    };
#else
    local_conf_case_t cases[] = {
        {LOCAL_CONF_AUTO,
         N00B_CONDUIT_LOCAL_AUTO,
         N00B_CONDUIT_LOCAL_UNIX,
         true,
         true},
        {LOCAL_CONF_EXPLICIT_UNIX,
         N00B_CONDUIT_LOCAL_UNIX,
         N00B_CONDUIT_LOCAL_UNIX,
         true,
         true},
    };
#endif

    uint64_t ncases = sizeof(cases) / sizeof(cases[0]);
#if defined(__APPLE__)
    assert(ncases == 3);
#else
    assert(ncases == 2);
#endif

    for (uint64_t i = 0; i < ncases; i++) {
        run_supported_case(cases[i]);
        run_multi_client_case(cases[i]);
        run_dead_endpoint_case(cases[i]);
        run_stale_unix_endpoint_case(cases[i]);
    }
}

static void
test_unsupported_backend_matrix(void)
{
#if defined(_WIN32)
    assert_unsupported_backend(N00B_CONDUIT_LOCAL_XPC);
    assert_unsupported_backend(N00B_CONDUIT_LOCAL_UNIX);
#elif defined(__APPLE__)
    assert_unsupported_backend(N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
#else
    assert_unsupported_backend(N00B_CONDUIT_LOCAL_XPC);
    assert_unsupported_backend(N00B_CONDUIT_LOCAL_WINDOWS_NAMED);
#endif
}

// Regression: accepted connections served by a shared bridge_pool instead of a
// dedicated per-connection bridge thread. Drives both the sequential
// connect/echo/close churn that previously spawned+reaped a thread per
// connection (the callstack-pool corruption signature) and an overlapping burst
// that exceeds the pool's worker count, exercising the queued-job path and the
// queued-but-not-yet-running close case. UNIX only: the bridge loop (and thus
// bridge_pool) is the FD-backed path; XPC/Windows use native conn handling.
#if defined(__APPLE__) || (!defined(_WIN32))
static void
run_bridge_pool_churn_case(void)
{
    n00b_conduit_t            *c    = make_conduit();
    n00b_conduit_io_backend_t *io   = make_io_via_service(c);
    n00b_string_t             *name = build_tmp_path();

    // size 2 / cap 2: small enough that the overlapping-burst phase below
    // (4 simultaneous connections) forces both queueing and accept-path
    // backpressure, the exact conditions the close-sync must survive.
    auto pool_r = n00b_conduit_local_bridge_pool_new(2, 2);
    assert(n00b_result_is_ok(pool_r));
    n00b_worker_pool_t *pool = n00b_result_get(pool_r);

    auto lr = n00b_conduit_local_listen(c, name,
                                        .backend      = N00B_CONDUIT_LOCAL_UNIX,
                                        .io           = io,
                                        .unlink_stale = true,
                                        .bridge_pool  = pool);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_local_listener_t *listener = n00b_result_get(lr);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_local_listener_accept_topic_typed(listener);
    assert(accept_topic != nullptr);
    n00b_conduit_local_accept_inbox_t *accept_inbox =
        n00b_conduit_local_accept_inbox_new(c);
    n00b_conduit_local_accept_subscribe(accept_topic, accept_inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    // Phase 1: sequential churn. Each iteration reuses a pool worker rather
    // than spawning a fresh thread. 24 iterations >> 2 workers proves reuse.
    for (int i = 0; i < 24; i++) {
        auto cr = n00b_conduit_local_connect(c, name,
                                             .backend = N00B_CONDUIT_LOCAL_UNIX,
                                             .io      = io);
        assert(n00b_result_is_ok(cr));
        n00b_conduit_local_conn_t *client = n00b_result_get(cr);
        n00b_conduit_local_conn_t *server =
            wait_for_accept(accept_inbox, N00B_CONDUIT_LOCAL_UNIX);

        write_buffer(client, "wp005-pool-churn",
                     LOCAL_CONF_LITERAL_LEN("wp005-pool-churn"));
        assert_read_buffer(server, "wp005-pool-churn",
                           LOCAL_CONF_LITERAL_LEN("wp005-pool-churn"));

        n00b_conduit_local_conn_close(client);
        n00b_conduit_local_conn_close(server);
    }

    // Phase 2: overlapping burst of 4 simultaneous connections against a
    // 2-worker pool. Two connections' bridge jobs run; the rest queue. Closing
    // every connection (including queued-but-not-yet-running ones) must not hang
    // or corrupt the pool.
    n00b_conduit_local_conn_t *clients[4];
    n00b_conduit_local_conn_t *servers[4];
    for (int i = 0; i < 4; i++) {
        auto cr = n00b_conduit_local_connect(c, name,
                                             .backend = N00B_CONDUIT_LOCAL_UNIX,
                                             .io      = io);
        assert(n00b_result_is_ok(cr));
        clients[i] = n00b_result_get(cr);
        servers[i] = wait_for_accept(accept_inbox, N00B_CONDUIT_LOCAL_UNIX);
    }
    for (int i = 0; i < 4; i++) {
        n00b_conduit_local_conn_close(clients[i]);
        n00b_conduit_local_conn_close(servers[i]);
    }

    n00b_conduit_local_listener_close(listener);
    (void)n00b_file_unlink(name, .ignore_missing = true);

    // Every connection is closed (bridge_stop set), so each bridge job -- running
    // or still queued -- exits at the top of its loop. Drain and join the pool
    // while the conduit is still alive (jobs read conn->conduit), THEN tear the
    // conduit down: no bridge job can be in-flight against a destroyed conduit.
    n00b_worker_pool_quiesce(pool);
    n00b_worker_pool_shutdown(pool);
    teardown_conduit(c);
}
#endif

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_unsupported_backend_matrix();
    test_supported_backend_matrix();
#if defined(__APPLE__) || (!defined(_WIN32))
    run_bridge_pool_churn_case();
#endif

    n00b_shutdown();
    return 0;
}

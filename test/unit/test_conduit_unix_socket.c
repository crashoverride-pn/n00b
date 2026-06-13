/*
 * test_conduit_unix_socket.c — AF_UNIX listen/connect tests for the
 * conduit socket layer.
 *
 * Covers the six acceptance gates from doc/wp031-burndown.md Phase 2:
 *
 *   1. listen + connect from the same process delivers exactly one
 *      sock_accept payload with a valid client_fd.
 *   2. conn_unix to a path with no listener returns errno directly
 *      before publishing a managed fd owner.
 *   3. A path that doesn't fit in sun_path returns ENAMETOOLONG —
 *      no silent truncation.
 *   4. unlink_stale=true removes a pre-existing regular file at the
 *      target path; calling without it on an existing socket fails
 *      with EADDRINUSE.
 *   5. mode=0600 leaves the socket file's mode at 0600.
 *   6. Immediate-success connect publishes CONNECTED.
 *
 * No pthread / pthread_cond / pthread_mutex anywhere. The conduit
 * machinery is the test target.
 */

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/socket.h"
#include "conduit/io.h"
#include "conduit/service.h"
#include "conduit/fd_managed.h"
#include "conduit/print.h"
#include "core/file.h"
#include "core/runtime.h"
#include "core/alloc.h"
#include "core/atomic.h"
#include "text/strings/fmt_numbers.h"
#include "util/path.h"

// ============================================================================
// Helpers
// ============================================================================

static n00b_conduit_t *
make_conduit(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    return n00b_result_get(cr);
}

/* Bring up the conduit's service thread pool and return its IO
 * backend. We deliberately use the service's IO backend instead of
 * creating a separate one via n00b_conduit_io_new_default — only the
 * service-owned backend has a poll thread running against it, so
 * FDs registered on any other backend will never see readiness
 * events. */
static n00b_conduit_io_backend_t *
make_io_via_service(n00b_conduit_t *c)
{
    n00b_result_t(n00b_conduit_service_t *) sr = n00b_conduit_service_new(c);
    assert(n00b_result_is_ok(sr));
    n00b_conduit_service_t *svc = n00b_result_get(sr);
    n00b_result_t(bool) rr = n00b_conduit_service_start(svc);
    assert(n00b_result_is_ok(rr));

    /* The default _start spawns one IO thread; grab its backend. */
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

/* Build a unique-per-test socket path under the temp root, using the
 * shared n00b temp-path machinery. The tag distinguishes tests within
 * the run; the random hex inside n00b_new_temp_path keeps concurrent
 * runs and rapid re-runs isolated. */
static n00b_string_t *
build_tmp_path(const char *tag)
{
    n00b_string_t *prefix = n00b_cformat("libn00b-unix-sock-«#»-",
                                          n00b_string_from_cstr(tag));
    n00b_string_t *suffix = n00b_string_from_cstr(".sock");
    n00b_string_t *path   = n00b_new_temp_path(prefix, suffix);
    (void)n00b_file_unlink(path, .ignore_missing = true);
    return path;
}

/* Tear down the conduit + its service. Tests must call this before
 * returning so n00b_shutdown() at the end of main() can run cleanly
 * instead of blocking on still-live service threads. */
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

// ============================================================================
// Tests
// ============================================================================

static void
test_listen_unix_accept_emits_event(void)
{
    n00b_conduit_t            *c    = make_conduit();
    n00b_conduit_io_backend_t *io   = make_io_via_service(c);
    n00b_string_t             *path = build_tmp_path("accept");

    auto lr = n00b_conduit_listen_unix(c, io, path, 16);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_listener_t *listener = n00b_result_get(lr);

    auto accept_topic_opt = n00b_conduit_listener_accept_topic(listener);
    assert(n00b_option_is_set(accept_topic_opt));
    n00b_conduit_topic_base_t *accept_topic = n00b_option_get(accept_topic_opt);

    n00b_conduit_sock_accept_inbox_t *inbox = n00b_conduit_sock_accept_inbox_new(c);
    n00b_conduit_sock_accept_subscribe(accept_topic, inbox,
                                        .operations = N00B_CONDUIT_OP_ALL);

    auto conn_r = n00b_conduit_conn_unix(c, io, path);
    assert(n00b_result_is_ok(conn_r));
    n00b_conduit_conn_t *conn = n00b_result_get(conn_r);

    // Service threads drive accept readiness — give them a moment.
    for (int i = 0; i < 200; i++) {
        if (n00b_conduit_sock_accept_inbox_has_messages(inbox)) {
            break;
        }
        usleep(5000);
    }
    assert(n00b_conduit_sock_accept_inbox_has_messages(inbox));

    n00b_conduit_sock_accept_msg_t *msg =
        n00b_conduit_sock_accept_inbox_pop(inbox);
    assert(msg != nullptr);
    assert(msg->payload.client_fd >= 0);
    // The accept event hands the caller a raw fd. Releasing it back to
    // the kernel is a libc-level operation (n00b doesn't wrap close(2)
    // for arbitrary fds; the conduit-managed alternative would be
    // n00b_conduit_fd_manage + later n00b_conduit_fd_close).
    (void)close(msg->payload.client_fd);

    n00b_conduit_conn_close(conn);
    n00b_conduit_listener_close(listener);
    (void)n00b_file_unlink(path, .ignore_missing = true);
    n00b_printf("  [PASS] listen + connect emits accept event");
    teardown_conduit(c);
}

static void
test_conn_unix_dead_path_returns_errno(void)
{
    n00b_conduit_t            *c    = make_conduit();
    n00b_conduit_io_backend_t *io   = make_io_via_service(c);
    n00b_string_t             *path = build_tmp_path("refused");

    auto conn_r = n00b_conduit_conn_unix(c, io, path);
    assert(n00b_result_is_err(conn_r));
    int err = n00b_result_get_err(conn_r);
    assert(err == ENOENT || err == ECONNREFUSED);
    n00b_printf("  [PASS] conn_unix to dead path returns errno [|#|]",
                 n00b_fmt_uint((uint64_t)err));
    teardown_conduit(c);
}

static void
test_conn_unix_stale_socket_returns_errno(void)
{
    n00b_conduit_t            *c    = make_conduit();
    n00b_conduit_io_backend_t *io   = make_io_via_service(c);
    n00b_string_t             *path = build_tmp_path("stale-closed");

    auto lr = n00b_conduit_listen_unix(c, io, path, 16);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_listener_close(n00b_result_get(lr));

    auto conn_r = n00b_conduit_conn_unix(c, io, path);
    assert(n00b_result_is_err(conn_r));
    int err = n00b_result_get_err(conn_r);
    assert(err == ENOENT || err == ECONNREFUSED);

    (void)n00b_file_unlink(path, .ignore_missing = true);
    n00b_printf("  [PASS] conn_unix to stale socket returns errno [|#|]",
                 n00b_fmt_uint((uint64_t)err));
    teardown_conduit(c);
}

static void
test_listen_unix_path_too_long_returns_enametoolong(void)
{
    n00b_conduit_t            *c  = make_conduit();
    n00b_conduit_io_backend_t *io = make_io_via_service(c);

    // sun_path is 104 on darwin / 108 on Linux — 512 is far over either.
    char raw[512];
    memset(raw, 'a', sizeof(raw) - 1);
    raw[sizeof(raw) - 1] = '\0';
    n00b_string_t *long_path = n00b_string_from_cstr(raw);

    auto lr = n00b_conduit_listen_unix(c, io, long_path, 16);
    assert(n00b_result_is_err(lr));
    assert(n00b_result_get_err(lr) == ENAMETOOLONG);
    n00b_printf("  [PASS] over-long path → ENAMETOOLONG");
    teardown_conduit(c);
}

static void
test_listen_unix_unlink_stale(void)
{
    n00b_conduit_t            *c    = make_conduit();
    n00b_conduit_io_backend_t *io   = make_io_via_service(c);
    n00b_string_t             *path = build_tmp_path("stale");

    // Pre-create a regular file at the target path using the n00b
    // file API; closing it leaves a zero-byte regular file behind.
    auto open_r = n00b_file_open(path, .mode = N00B_FILE_W);
    assert(n00b_result_is_ok(open_r));
    n00b_file_close(n00b_result_get(open_r));

    // Without unlink_stale, bind should fail with EADDRINUSE.
    auto lr_bad = n00b_conduit_listen_unix(c, io, path, 16);
    assert(n00b_result_is_err(lr_bad));
    assert(n00b_result_get_err(lr_bad) == EADDRINUSE);

    // With unlink_stale, it succeeds and the file is now a socket.
    auto lr_good = n00b_conduit_listen_unix(c, io, path, 16,
                                              .unlink_stale = true);
    assert(n00b_result_is_ok(lr_good));

    assert(n00b_get_file_kind(path) == N00B_FK_IS_SOCK);

    n00b_conduit_listener_close(n00b_result_get(lr_good));
    (void)n00b_file_unlink(path, .ignore_missing = true);
    n00b_printf("  [PASS] unlink_stale replaces a stale file with a socket");
    teardown_conduit(c);
}

static void
test_listen_unix_mode_chmod(void)
{
    n00b_conduit_t            *c    = make_conduit();
    n00b_conduit_io_backend_t *io   = make_io_via_service(c);
    n00b_string_t             *path = build_tmp_path("mode");

    auto lr = n00b_conduit_listen_unix(c, io, path, 16, .mode = 0600);
    assert(n00b_result_is_ok(lr));

    assert(n00b_get_file_kind(path) == N00B_FK_IS_SOCK);
    auto mode_r = n00b_path_get_mode(path);
    assert(n00b_result_is_ok(mode_r));
    assert((n00b_result_get(mode_r) & 0777) == 0600);

    n00b_conduit_listener_close(n00b_result_get(lr));
    (void)n00b_file_unlink(path, .ignore_missing = true);
    n00b_printf("  [PASS] mode kwarg chmods the socket file");
    teardown_conduit(c);
}

static void
test_conn_unix_immediate_success_publishes_connected(void)
{
    n00b_conduit_t            *c    = make_conduit();
    n00b_conduit_io_backend_t *io   = make_io_via_service(c);
    n00b_string_t             *path = build_tmp_path("connected");

    auto lr = n00b_conduit_listen_unix(c, io, path, 16);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_listener_t *listener = n00b_result_get(lr);

    auto conn_r = n00b_conduit_conn_unix(c, io, path);
    assert(n00b_result_is_ok(conn_r));
    n00b_conduit_conn_t *conn = n00b_result_get(conn_r);

    /* AF_UNIX connect completes before fd-owner registration. The returned
     * conn is already CONNECTED; the status topic is for transitions from
     * that point forward (CLOSED, RESET, ERROR). */
    int initial_state = n00b_atomic_load(&conn->conn_state);
    assert(initial_state == N00B_CONDUIT_CONN_ST_CONNECTED);
    n00b_printf("  [PASS] conn_unix synchronously transitioned to CONNECTED");

    n00b_conduit_conn_close(conn);
    n00b_conduit_listener_close(listener);
    (void)n00b_file_unlink(path, .ignore_missing = true);
    teardown_conduit(c);
}

// ============================================================================
// Entry point
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_listen_unix_path_too_long_returns_enametoolong();
    test_listen_unix_mode_chmod();
    test_listen_unix_unlink_stale();
    test_conn_unix_dead_path_returns_errno();
    test_conn_unix_stale_socket_returns_errno();
    test_listen_unix_accept_emits_event();
    test_conn_unix_immediate_success_publishes_connected();

    n00b_printf("All test_conduit_unix_socket tests passed.");
    n00b_shutdown();
    return 0;
}

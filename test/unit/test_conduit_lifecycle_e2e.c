/*
 * test_conduit_lifecycle_e2e.c — conduit fd/socket lifecycle tests.
 *
 * Exercises close idempotence, registry removal, fd-number reuse, listener
 * teardown, and connection teardown through public conduit/socket/fd APIs.
 */

#include <assert.h>
#include <stdio.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/fd_managed.h"
#include "conduit/io.h"
#include "conduit/service.h"
#include "conduit/socket.h"
#include "core/atomic.h"
#include "core/file.h"
#include "core/runtime.h"
#include "util/path.h"

#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

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
    auto rr = n00b_conduit_service_start(svc);
    assert(n00b_result_is_ok(rr));

    int n = n00b_atomic_load(&svc->num_threads);
    for (int i = 0; i < n; i++) {
        n00b_conduit_svc_thread_t *t = svc->threads[i];
        if (t != nullptr && t->role == N00B_CONDUIT_SVC_IO && t->io != nullptr) {
            return t->io;
        }
    }

    assert(!"service did not spawn an IO thread");
    return nullptr;
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

#ifndef _WIN32

static n00b_string_t *
build_tmp_path(n00b_string_t *tag)
{
    char prefix_buf[128];
    int  prefix_len = snprintf(prefix_buf,
                              sizeof(prefix_buf),
                              "libn00b-lifecycle-%.*s-",
                              (int)tag->u8_bytes,
                              tag->data);
    assert(prefix_len > 0);
    assert((size_t)prefix_len < sizeof(prefix_buf));

    n00b_string_t *prefix = n00b_string_from_cstr(prefix_buf);
    n00b_string_t *suffix = n00b_string_from_cstr(".sock");
    n00b_string_t *path   = n00b_new_temp_path(prefix, suffix);
    (void)n00b_file_unlink(path, .ignore_missing = true);
    return path;
}

static void
close_raw_fd(int fd)
{
    if (fd >= 0) {
        (void)close(fd);
    }
}

static void
make_pipe(int fds[2])
{
    assert(pipe(fds) == 0);
}

static void
test_fd_owner_repeated_close_and_registry_remove(void)
{
    n00b_conduit_t            *c  = make_conduit();
    n00b_conduit_io_backend_t *io = make_io_via_service(c);

    int fds[2];
    make_pipe(fds);
    int managed_fd = fds[0];

    auto manage_r = n00b_conduit_fd_manage(c, io, managed_fd, true);
    assert(n00b_result_is_ok(manage_r));
    n00b_conduit_fd_owner_t *owner = n00b_result_get(manage_r);

    auto close_r = n00b_conduit_fd_owner_close_result(owner);
    assert(n00b_result_is_ok(close_r));
    assert(n00b_result_get(close_r));
    assert(n00b_atomic_load(&owner->close_generation) == 1);
    assert(n00b_atomic_load(&owner->registry_registered) == false);
    assert(n00b_atomic_load(&owner->native_released));
    assert(n00b_atomic_load(&owner->terminal_status_count) == 1);

    auto lookup = n00b_conduit_fd_get_owner(c, managed_fd);
    assert(!n00b_option_is_set(lookup));

    auto close_again = n00b_conduit_fd_owner_close_result(owner);
    assert(n00b_result_is_ok(close_again));
    assert(!n00b_result_get(close_again));
    assert(n00b_atomic_load(&owner->close_generation) == 1);
    assert(n00b_atomic_load(&owner->terminal_status_count) == 1);

    close_raw_fd(fds[1]);
    teardown_conduit(c);
    puts("  [PASS] fd owner repeated close removes registry state");
}

static void
test_fd_owner_fd_number_reuse_gets_fresh_owner(void)
{
    n00b_conduit_t            *c  = make_conduit();
    n00b_conduit_io_backend_t *io = make_io_via_service(c);

    int first[2];
    make_pipe(first);
    int reused_fd = first[0];

    auto manage_r = n00b_conduit_fd_manage(c, io, reused_fd, true);
    assert(n00b_result_is_ok(manage_r));
    n00b_conduit_fd_owner_t *old_owner = n00b_result_get(manage_r);

    auto close_r = n00b_conduit_fd_owner_close_result(old_owner);
    assert(n00b_result_is_ok(close_r));
    assert(n00b_result_get(close_r));
    close_raw_fd(first[1]);

    int second[2];
    make_pipe(second);
    int new_read = second[0];
    if (new_read != reused_fd) {
        assert(dup2(new_read, reused_fd) == reused_fd);
        close_raw_fd(new_read);
        new_read = reused_fd;
    }

    auto second_manage_r = n00b_conduit_fd_manage(c, io, new_read, true);
    assert(n00b_result_is_ok(second_manage_r));
    n00b_conduit_fd_owner_t *new_owner = n00b_result_get(second_manage_r);

    assert(new_owner->fd == reused_fd);
    assert(n00b_atomic_load(&new_owner->state) == N00B_CONDUIT_FD_ACTIVE);
    assert(n00b_atomic_load(&new_owner->close_generation) == 0);
    assert(n00b_atomic_load(&new_owner->registry_registered));

    auto lookup = n00b_conduit_fd_get_owner(c, reused_fd);
    assert(n00b_option_is_set(lookup));
    assert(n00b_option_get(lookup) == new_owner);

    n00b_conduit_fd_owner_close(new_owner);
    close_raw_fd(second[1]);
    teardown_conduit(c);
    puts("  [PASS] fd number reuse gets fresh owner");
}

static void
test_listener_repeated_close(void)
{
    n00b_conduit_t            *c    = make_conduit();
    n00b_conduit_io_backend_t *io   = make_io_via_service(c);
    n00b_string_t             *path = build_tmp_path(r"listener");

    auto lr = n00b_conduit_listen_unix(c, io, path, 8);
    assert(n00b_result_is_ok(lr));
    n00b_conduit_listener_t *listener = n00b_result_get(lr);
    int fd = listener->fd;

    n00b_conduit_listener_close(listener);
    n00b_conduit_listener_close(listener);

    assert(n00b_atomic_load(&listener->close_generation) == 1);
    assert(n00b_atomic_load(&listener->active) == false);
    assert(n00b_atomic_load(&listener->registry_registered) == false);
    assert(n00b_atomic_load(&listener->native_released));

    auto lookup = n00b_conduit_listener_get(c, fd);
    assert(!n00b_option_is_set(lookup));

    (void)n00b_file_unlink(path, .ignore_missing = true);
    teardown_conduit(c);
    puts("  [PASS] listener repeated close is idempotent");
}

static void
test_conn_repeated_close_closes_owner_once(void)
{
    n00b_conduit_t            *c  = make_conduit();
    n00b_conduit_io_backend_t *io = make_io_via_service(c);

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    int conn_fd = fds[0];

    auto conn_r = n00b_conduit_conn_from_fd(c, io, conn_fd);
    assert(n00b_result_is_ok(conn_r));
    n00b_conduit_conn_t *conn = n00b_result_get(conn_r);

    auto owner_opt = n00b_conduit_conn_fd_owner(conn);
    assert(n00b_option_is_set(owner_opt));
    n00b_conduit_fd_owner_t *owner = n00b_option_get(owner_opt);

    n00b_conduit_conn_close(conn);
    n00b_conduit_conn_close(conn);

    assert(n00b_atomic_load(&conn->close_generation) == 1);
    assert(n00b_atomic_load(&conn->terminal_status_count) == 1);
    assert(n00b_atomic_load(&owner->close_generation) == 1);
    assert(n00b_atomic_load(&owner->registry_registered) == false);
    assert(n00b_atomic_load(&owner->native_released));

    auto lookup = n00b_conduit_fd_get_owner(c, conn_fd);
    assert(!n00b_option_is_set(lookup));

    close_raw_fd(fds[1]);
    teardown_conduit(c);
    puts("  [PASS] conn repeated close closes owner once");
}

#endif

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    puts("test_conduit_lifecycle_e2e:");

#ifdef _WIN32
    puts("  [SKIP] POSIX fd/socket lifecycle cases on Windows");
#else
    test_fd_owner_repeated_close_and_registry_remove();
    test_fd_owner_fd_number_reuse_gets_fresh_owner();
    test_listener_repeated_close();
    test_conn_repeated_close_closes_owner_once();
#endif

    n00b_shutdown();
    return 0;
}

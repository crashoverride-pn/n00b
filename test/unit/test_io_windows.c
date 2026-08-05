#ifdef _WIN32
#include "internal/win32_sockets.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "core/runtime.h"

#ifdef _WIN32
static void
close_socket_if_valid(SOCKET s)
{
    if (s != INVALID_SOCKET) {
        closesocket(s);
    }
}

static bool
make_connected_sockets(SOCKET *read_socket, SOCKET *write_socket)
{
    SOCKET listener = INVALID_SOCKET;
    SOCKET reader   = INVALID_SOCKET;
    SOCKET writer   = INVALID_SOCKET;

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        goto fail;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;

    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        goto fail;
    }

    int addr_len = sizeof(addr);
    if (getsockname(listener, (struct sockaddr *)&addr, &addr_len) == SOCKET_ERROR) {
        goto fail;
    }

    if (listen(listener, 1) == SOCKET_ERROR) {
        goto fail;
    }

    writer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (writer == INVALID_SOCKET) {
        goto fail;
    }

    if (connect(writer, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        goto fail;
    }

    reader = accept(listener, NULL, NULL);
    if (reader == INVALID_SOCKET) {
        goto fail;
    }

    closesocket(listener);
    *read_socket  = reader;
    *write_socket = writer;
    return true;

fail:
    close_socket_if_valid(reader);
    close_socket_if_valid(writer);
    close_socket_if_valid(listener);
    return false;
}

static void
test_default_wsa_backend_delivers_socket_readiness(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_io_backend_t *) ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    n00b_string_t *name = n00b_conduit_io_name(io);
    assert(name != nullptr);
    assert(name->u8_bytes == 3);
    assert(memcmp(name->data, "wsa", 3) == 0);

    SOCKET reader = INVALID_SOCKET;
    SOCKET writer = INVALID_SOCKET;
    assert(make_connected_sockets(&reader, &writer));

    n00b_result_t(n00b_conduit_topic_base_t *) wr =
        n00b_conduit_io_watch(io, reader, N00B_CONDUIT_IO_READ, nullptr);
    assert(n00b_result_is_ok(wr));

    char byte = 'x';
    assert(send(writer, &byte, 1, 0) == 1);

    n00b_result_t(int) pr = n00b_conduit_io_poll(io, 1000);
    assert(n00b_result_is_ok(pr));
    assert(n00b_result_get(pr) > 0);

    n00b_conduit_io_unwatch(io, reader);
    close_socket_if_valid(reader);
    close_socket_if_valid(writer);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);

    printf("  [PASS] default_wsa_backend_delivers_socket_readiness\n");
}
#endif

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

#ifdef _WIN32
    printf("Running Windows conduit I/O tests...\n");
    test_default_wsa_backend_delivers_socket_readiness();
    printf("All Windows conduit I/O tests passed.\n");
#else
    (void)argc;
    (void)argv;
#endif

    n00b_shutdown();
    return 0;
}

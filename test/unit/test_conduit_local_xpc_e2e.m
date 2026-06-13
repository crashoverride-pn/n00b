/*
 * test_conduit_local_xpc_e2e.m - Darwin XPC local IPC skeleton test.
 *
 * This Phase 1 test uses only the public local IPC API. The Meson target is
 * Darwin-only; the source is copied to a generated .c file so ncc, not the
 * system Objective-C frontend, compiles the public n00b headers.
 */

#include <assert.h>

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
test_local_xpc_skeleton_not_supported(void)
{
    n00b_conduit_t *c    = make_conduit();
    n00b_string_t  *name = r"wp003-xpc-skeleton";

    auto lr = n00b_conduit_local_listen(c, name,
                                        .backend = N00B_CONDUIT_LOCAL_XPC);
    assert(n00b_result_is_err(lr));
    assert(n00b_result_get_err(lr) == N00B_CONDUIT_ERR_NOT_SUPPORTED);

    auto cr = n00b_conduit_local_connect(c, name,
                                         .backend = N00B_CONDUIT_LOCAL_XPC);
    assert(n00b_result_is_err(cr));
    assert(n00b_result_get_err(cr) == N00B_CONDUIT_ERR_NOT_SUPPORTED);

    n00b_conduit_destroy(c);
}

static void
test_local_xpc_auto_skeleton_not_supported(void)
{
    n00b_conduit_t *c    = make_conduit();
    n00b_string_t  *name = r"wp003-xpc-auto-skeleton";

    auto lr = n00b_conduit_local_listen(c, name);
    assert(n00b_result_is_err(lr));
    assert(n00b_result_get_err(lr) == N00B_CONDUIT_ERR_NOT_SUPPORTED);

    auto cr = n00b_conduit_local_connect(c, name);
    assert(n00b_result_is_err(cr));
    assert(n00b_result_get_err(cr) == N00B_CONDUIT_ERR_NOT_SUPPORTED);

    n00b_conduit_destroy(c);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_local_xpc_public_header_shape();
    test_local_xpc_skeleton_not_supported();
    test_local_xpc_auto_skeleton_not_supported();

    n00b_shutdown();
    return 0;
}

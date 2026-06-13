/*
 * test_conduit_local_windows_e2e.c - Windows named local IPC skeleton test.
 *
 * Phase 1 verifies the public local IPC header shape for the Windows backend.
 * Behavioral named-pipe listener/connect/data-path coverage lands in later
 * WP-004 phases. This file is registered only for Windows builds.
 */

#include <assert.h>

#include "n00b.h"
#include "conduit/local.h"
#include "core/runtime.h"

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

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_local_windows_public_header_shape();

    n00b_shutdown();
    return 0;
}

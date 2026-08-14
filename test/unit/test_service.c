/*
 * test_service.c — Tests for the conduit service thread pool.
 */

#include <stdio.h>
#include <assert.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/service.h"
#include "core/alloc.h"
#include "core/runtime.h"

// ============================================================================
// 1. Service create / destroy
// ============================================================================

static void
test_service_create(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_service_t *) sr = n00b_conduit_service_new(c);
    assert(n00b_result_is_ok(sr));

    n00b_conduit_service_t *svc = n00b_result_get(sr);
    assert(svc != nullptr);

    // The service should be stored on the conduit.
    assert(c->service == svc);

    n00b_conduit_service_destroy(svc);
    n00b_conduit_destroy(c);
    printf("  [PASS] service create/destroy\n");
}

// ============================================================================
// 2. Service start / stop
// ============================================================================

static void
test_service_start_stop(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_service_t *) sr = n00b_conduit_service_new(c);
    assert(n00b_result_is_ok(sr));
    n00b_conduit_service_t *svc = n00b_result_get(sr);

    n00b_result_t(bool) br = n00b_conduit_service_start(svc);
    assert(n00b_result_is_ok(br));

    // Service must report itself as started.
    assert(n00b_atomic_load(&svc->started));

    // At least one IO thread must have been spawned.
    int num = n00b_atomic_load(&svc->num_threads);
    assert(num >= 1);

    // The default IO thread must be present and carry the IO role.
    n00b_option_t(n00b_conduit_svc_thread_t *) opt =
        n00b_conduit_service_default_io(svc);
    assert(n00b_option_is_set(opt));

    n00b_conduit_svc_thread_t *st = n00b_option_get(opt);
    assert(st != nullptr);
    assert(st->role == N00B_CONDUIT_SVC_IO);

    // Private services must not spawn process signal backends.
    n00b_option_t(n00b_conduit_svc_thread_t *) sig_opt =
        n00b_conduit_service_signal_io(svc);
    assert(!n00b_option_is_set(sig_opt));

    n00b_conduit_service_stop(svc);
    n00b_conduit_service_destroy(svc);
    n00b_conduit_destroy(c);
    printf("  [PASS] service start/stop\n");
}

// ============================================================================
// 3. Service add extra IO thread
// ============================================================================

static void
test_service_add_io(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_service_t *) sr = n00b_conduit_service_new(c);
    assert(n00b_result_is_ok(sr));
    n00b_conduit_service_t *svc = n00b_result_get(sr);

    n00b_result_t(bool) br = n00b_conduit_service_start(svc);
    assert(n00b_result_is_ok(br));

    int before = n00b_atomic_load(&svc->num_threads);
    assert(before >= 1);

    // Add a second IO thread using the platform-default backend ops.
    n00b_result_t(n00b_conduit_svc_thread_t *) tr =
        n00b_conduit_service_add_io(svc, n00b_result_get(n00b_conduit_io_default_ops()));
    assert(n00b_result_is_ok(tr));

    n00b_conduit_svc_thread_t *extra = n00b_result_get(tr);
    assert(extra != nullptr);

    // Thread count must have grown.
    int after = n00b_atomic_load(&svc->num_threads);
    assert(after > before);

    n00b_conduit_service_stop(svc);
    n00b_conduit_service_destroy(svc);
    n00b_conduit_destroy(c);
    printf("  [PASS] service add IO thread\n");
}

// ============================================================================
// 4. Idempotent start (calling start twice must not error)
// ============================================================================

static void
test_service_idempotent_start(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_service_t *) sr = n00b_conduit_service_new(c);
    assert(n00b_result_is_ok(sr));
    n00b_conduit_service_t *svc = n00b_result_get(sr);

    n00b_result_t(bool) br1 = n00b_conduit_service_start(svc);
    assert(n00b_result_is_ok(br1));

    // Second start must not crash and must return ok.
    n00b_result_t(bool) br2 = n00b_conduit_service_start(svc);
    assert(n00b_result_is_ok(br2));

    // Thread count must not have doubled.
    int num = n00b_atomic_load(&svc->num_threads);
    assert(num >= 1);

    n00b_conduit_service_stop(svc);
    n00b_conduit_service_destroy(svc);
    n00b_conduit_destroy(c);
    printf("  [PASS] idempotent start\n");
}

// ============================================================================
// 5. Double stop (calling stop twice must not crash)
// ============================================================================

static void
test_service_double_stop(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_service_t *) sr = n00b_conduit_service_new(c);
    assert(n00b_result_is_ok(sr));
    n00b_conduit_service_t *svc = n00b_result_get(sr);

    n00b_result_t(bool) br = n00b_conduit_service_start(svc);
    assert(n00b_result_is_ok(br));

    n00b_conduit_service_stop(svc);
    // Second stop must not crash.
    n00b_conduit_service_stop(svc);

    n00b_conduit_service_destroy(svc);
    n00b_conduit_destroy(c);
    printf("  [PASS] double stop\n");
}

// ============================================================================
// 6. service_new twice returns same service
// ============================================================================

static void
test_service_new_twice(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_service_t *) sr1 = n00b_conduit_service_new(c);
    assert(n00b_result_is_ok(sr1));
    n00b_conduit_service_t *svc1 = n00b_result_get(sr1);

    // Second call must return the same service.
    n00b_result_t(n00b_conduit_service_t *) sr2 = n00b_conduit_service_new(c);
    assert(n00b_result_is_ok(sr2));
    n00b_conduit_service_t *svc2 = n00b_result_get(sr2);

    assert(svc1 == svc2);

    n00b_conduit_service_destroy(svc1);
    n00b_conduit_destroy(c);
    printf("  [PASS] service new twice\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

#ifndef _WIN32
    // The runtime default service is the sole owner of process signal I/O.
    n00b_runtime_t *active_rt = n00b_get_runtime();
    assert(active_rt != nullptr);
    assert(active_rt->default_service != nullptr);
    n00b_option_t(n00b_conduit_svc_thread_t *) default_sig =
        n00b_conduit_service_signal_io(active_rt->default_service);
    assert(n00b_option_is_set(default_sig));
#endif

    printf("test_service:\n");
    fflush(stdout);

    test_service_create();
    fflush(stdout);
    test_service_start_stop();
    fflush(stdout);
    test_service_add_io();
    fflush(stdout);
    test_service_idempotent_start();
    fflush(stdout);
    test_service_double_stop();
    fflush(stdout);
    test_service_new_twice();
    fflush(stdout);

    printf("All service tests passed.\n");
    n00b_shutdown();
    return 0;
}

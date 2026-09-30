/*
 * test_http_client.c — Phase 6 chunk 5 unit tests for the public
 * dispatcher.
 *
 * Argument validation + URL passthrough + transport-tag wiring.
 * Network exercise lives in test_http_client_network.c (gated).
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/pool.h"
#include "adt/result.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/service.h"
#include "core/platform.h"
#include "core/thread.h"
#include "net/http/http_client.h"
#include "internal/net/http/http_client.h"
#include "internal/net/http/http_url.h"

static void
test_null_url(void)
{
    auto r = n00b_http_request_sync(nullptr);
    assert(n00b_result_is_err(r));
    assert((int)n00b_result_get_err(r) == N00B_HTTP_ERR_NULL_ARG);
    printf("  [PASS] nullptr url → NULL_ARG\n");
}

static void
test_unsupported_scheme(void)
{
    auto r = n00b_http_request_sync(n00b_string_from_cstr(
        "http://example.com/"));
    assert(n00b_result_is_err(r));
    assert((int)n00b_result_get_err(r) == N00B_HTTP_ERR_UNSUPPORTED_SCHEME);
    printf("  [PASS] http:// rejected at the dispatcher\n");
}

static void
test_unresolvable_h1_only(void)
{
    /* prefer_h3=false short-circuits straight to h1, which uses
     * blocking gethostbyname through the acme_tls layer.  An
     * unresolvable host should error promptly rather than hang. */
    n00b_http_loss_cache_reset();
    auto r = n00b_http_request_sync(
        n00b_string_from_cstr(
            "https://this-host-must-not-resolve.invalid./"),
        .prefer_h3 = false,
        .timeout_ms = 1000);
    assert(n00b_result_is_err(r));
    /* The h1 transport propagates whatever the TLS shim returns —
     * exact code depends on which step fails, so just assert the
     * call returned a negative code. */
    assert((int)n00b_result_get_err(r) < 0);
    printf("  [PASS] unresolvable host (h1-only) errors cleanly\n");
}

static void
test_loss_cache_reset(void)
{
    /* Reset is always callable; idempotent on cold cache. */
    n00b_http_loss_cache_reset();
    n00b_http_loss_cache_reset();
    printf("  [PASS] loss cache reset is callable + idempotent\n");
}

static void
test_topic_request_null_args(void)
{
    auto cr = n00b_conduit_new();
    n00b_conduit_t *c = n00b_result_get(cr);

    /* null conduit. */
    auto r1 = n00b_http_request(nullptr,
                                 n00b_string_from_cstr("https://example.com/"));
    assert(n00b_result_is_err(r1));
    assert((int32_t)n00b_result_get_err(r1) == N00B_HTTP_ERR_NULL_ARG);

    /* null url. */
    auto r2 = n00b_http_request(c, nullptr);
    assert(n00b_result_is_err(r2));
    assert((int32_t)n00b_result_get_err(r2) == N00B_HTTP_ERR_NULL_ARG);

    n00b_conduit_destroy(c);
    printf("  [PASS] n00b_http_request rejects nullptr conduit/url\n");
}

static void
test_redirect_status_classification(void)
{
    /* Per RFC 9110 § 15.4. */
    assert(n00b_http_status_is_redirect(301));
    assert(n00b_http_status_is_redirect(302));
    assert(n00b_http_status_is_redirect(303));
    assert(n00b_http_status_is_redirect(307));
    assert(n00b_http_status_is_redirect(308));
    assert(!n00b_http_status_is_redirect(200));
    assert(!n00b_http_status_is_redirect(304));   /* Not Modified — not a follow */
    assert(!n00b_http_status_is_redirect(305));   /* Use Proxy — deprecated */
    assert(!n00b_http_status_is_redirect(404));

    /* 301/302/303 collapse to GET; 307/308 preserve method. */
    assert(!n00b_http_status_preserves_method(301));
    assert(!n00b_http_status_preserves_method(302));
    assert(!n00b_http_status_preserves_method(303));
    assert(n00b_http_status_preserves_method(307));
    assert(n00b_http_status_preserves_method(308));
    printf("  [PASS] redirect status classification matches RFC 9110\n");
}

static void
test_topic_request_unsupported_scheme(void)
{
    /* Topic-shaped path returns the topic immediately; the worker
     * publishes an error response with non-zero `error` on transport
     * / URL failures.  This test sets up a fake URL that fails URL
     * parsing and confirms the error reaches the topic. */
    auto cr = n00b_conduit_new();
    n00b_conduit_t *c = n00b_result_get(cr);

    auto tr = n00b_http_request(c,
                                 n00b_string_from_cstr("ftp://example.com/"));
    assert(n00b_result_is_ok(tr));
    n00b_conduit_topic_t(n00b_http_response_t *) *t = n00b_result_get(tr);

    auto rr = n00b_conduit_read(n00b_http_response_t *, t,
                                .timeout_ms = 5000);
    assert(n00b_result_is_ok(rr));
    n00b_conduit_message_t(n00b_http_response_t *) *m = n00b_result_get(rr);
    n00b_http_response_t *resp = m->payload;
    assert(resp);
    assert(n00b_http_response_status(resp) == 0);
    assert(n00b_http_response_error(resp) == N00B_HTTP_ERR_UNSUPPORTED_SCHEME);

    n00b_conduit_destroy(c);
    printf("  [PASS] topic publishes error response on URL failure\n");
}

static void
test_topic_request_runs_on_conduit_service(void)
{
    /* The worker closes the response topic after publishing, so it has to
     * run on the conduit's service, which n00b_conduit_destroy stops and
     * waits for before it frees topics. A worker on its own thread can
     * close a freed topic, or the next request's topic in the same memory. */
    auto cr = n00b_conduit_new();
    n00b_conduit_t *c = n00b_result_get(cr);

    auto tr = n00b_http_request(c,
                                 n00b_string_from_cstr("ftp://example.com/"));
    assert(n00b_result_is_ok(tr));
    auto rr = n00b_conduit_read(n00b_http_response_t *, n00b_result_get(tr),
                                .timeout_ms = 5000);
    assert(n00b_result_is_ok(rr));

    assert(c->service != nullptr);
    assert(n00b_atomic_load(&c->service->started));
    assert(n00b_atomic_load(&c->service->worker_threads) > 0);

    n00b_conduit_destroy(c);
    printf("  [PASS] topic request runs on the conduit service\n");
}

#ifdef N00B_DEBUG
enum {
    CLOSE_PROBE_PENDING,
    CLOSE_PROBE_BEFORE_FREE,
    CLOSE_PROBE_AFTER_FREE,
};

static n00b_conduit_t            *close_probe_conduit;
static n00b_conduit_topic_base_t *close_probe_topic;
static _Atomic(bool)              close_probe_destroyed;
static _Atomic(int)               close_probe_outcome;

/* True once n00b_conduit_destroy has told the service thread running the
 * caller to stop, so destroy joins this thread before it frees topics. */
static bool
close_probe_destroy_waits_for_this_thread(void)
{
    n00b_conduit_service_t *svc = close_probe_conduit->service;
    if (!svc) {
        return false;
    }
    n00b_thread_t *self = n00b_thread_self();
    int            n    = n00b_atomic_load(&svc->num_threads);
    for (int i = 0; i < n; i++) {
        n00b_conduit_svc_thread_t *st = svc->threads[i];
        if (st && st->thread == self && n00b_atomic_load(&st->stop)) {
            return true;
        }
    }
    return false;
}

/* Holds the worker after delivery and before its close until destroy either
 * returns or waits on this thread, then records which came first. */
static void
close_probe_hook(n00b_conduit_topic_base_t *topic)
{
    if (topic != close_probe_topic) {
        return;
    }
    while (!n00b_atomic_load(&close_probe_destroyed)
           && !close_probe_destroy_waits_for_this_thread()) {
        base_nanosleep_ns(1000000);
    }
    if (!n00b_atomic_load(&close_probe_destroyed)) {
        n00b_atomic_store(&close_probe_outcome, CLOSE_PROBE_BEFORE_FREE);
        return;
    }
    n00b_atomic_store(&close_probe_outcome, CLOSE_PROBE_AFTER_FREE);
    /* The topic is freed. Park here so the close never lands on it. */
    for (;;) {
        base_nanosleep_ns(100000000);
    }
}
#endif

static void
test_topic_request_closes_topic_before_destroy_frees_it(void)
{
#ifdef N00B_DEBUG
    auto cr = n00b_conduit_new();
    n00b_conduit_t *c = n00b_result_get(cr);

    auto tr = n00b_http_request(c,
                                 n00b_string_from_cstr("ftp://example.com/"));
    assert(n00b_result_is_ok(tr));
    close_probe_conduit = c;
    close_probe_topic   = (n00b_conduit_topic_base_t *)n00b_result_get(tr);
    n00b_atomic_store(&close_probe_destroyed, false);
    n00b_atomic_store(&close_probe_outcome, CLOSE_PROBE_PENDING);
    n00b_http_test_before_response_close = close_probe_hook;

    auto rr = n00b_conduit_read(n00b_http_response_t *, n00b_result_get(tr),
                                .timeout_ms = 5000);
    assert(n00b_result_is_ok(rr));

    n00b_conduit_destroy(c);
    n00b_atomic_store(&close_probe_destroyed, true);

    /* Hang bound only: the hook reports as soon as it is released. */
    for (int i = 0; i < 60000
                    && n00b_atomic_load(&close_probe_outcome)
                           == CLOSE_PROBE_PENDING;
         i++) {
        base_nanosleep_ns(1000000);
    }
    int outcome = n00b_atomic_load(&close_probe_outcome);
    if (outcome == CLOSE_PROBE_AFTER_FREE) {
        fprintf(stderr,
                "  [FAIL] worker reached the response topic close after "
                "n00b_conduit_destroy freed the topic\n");
    }
    assert(outcome == CLOSE_PROBE_BEFORE_FREE);

    n00b_http_test_before_response_close = nullptr;
    printf("  [PASS] response topic closes before destroy frees it\n");
#endif
}

static void
test_topic_request_survives_caller_allocator_destroy(void)
{
    /* The async topic path must not retain request args in the caller's
     * allocator. Gateway egress passes a per-batch allocator, then can tear it
     * down after a transport failure while the HTTP worker is still publishing
     * its response. */
    auto cr = n00b_conduit_new();
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_pool_t       pool  = {};
    n00b_allocator_t *alloc = n00b_pool_init(&pool,
                                             .use_epochs = false,
                                             .name       = "http_test_call");

    n00b_string_t *url =
        n00b_string_from_cstr("ftp://example.com/", .allocator = alloc);
    n00b_string_t *method = n00b_string_from_cstr("POST", .allocator = alloc);
    n00b_buffer_t *body   = n00b_buffer_from_bytes("payload", 7,
                                                   .allocator = alloc);

    auto tr = n00b_http_request(c, url,
                                .method    = method,
                                .body      = body,
                                .allocator = alloc);
    assert(n00b_result_is_ok(tr));
    n00b_conduit_topic_t(n00b_http_response_t *) *t = n00b_result_get(tr);

    n00b_allocator_destroy(alloc);

    auto rr = n00b_conduit_read(n00b_http_response_t *, t,
                                .timeout_ms = 5000);
    assert(n00b_result_is_ok(rr));
    n00b_conduit_message_t(n00b_http_response_t *) *m = n00b_result_get(rr);
    n00b_http_response_t *resp = m->payload;
    assert(resp);
    assert(n00b_http_response_status(resp) == 0);
    assert(n00b_http_response_error(resp) == N00B_HTTP_ERR_UNSUPPORTED_SCHEME);

    n00b_conduit_destroy(c);
    printf("  [PASS] async request survives caller allocator teardown\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_http_client:\n");
    test_null_url();
    test_unsupported_scheme();
    test_unresolvable_h1_only();
    test_loss_cache_reset();
    test_topic_request_null_args();
    test_topic_request_unsupported_scheme();
    test_topic_request_closes_topic_before_destroy_frees_it();
    test_topic_request_runs_on_conduit_service();
    test_topic_request_survives_caller_allocator_destroy();
    test_redirect_status_classification();
    printf("All test_http_client tests passed.\n");

    n00b_shutdown();
    return 0;
}

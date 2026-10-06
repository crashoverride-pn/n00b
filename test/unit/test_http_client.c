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

#ifdef N00B_DEBUG
static n00b_conduit_topic_base_t *overlap_first;
static _Atomic(bool)              overlap_second_ran;
static _Atomic(bool)              overlap_first_saw_second;
static _Atomic(bool)              overlap_first_done;

/* Holds the first request's worker until the second request's worker
 * reaches the same point, and records whether it did. */
static void
overlap_hook(n00b_conduit_topic_base_t *topic)
{
    if (topic != overlap_first) {
        n00b_atomic_store(&overlap_second_ran, true);
        return;
    }
    /* Hang bound only: a passing run is released as soon as the second
     * worker arrives. */
    for (int i = 0; i < 20000 && !n00b_atomic_load(&overlap_second_ran);
         i++) {
        base_nanosleep_ns(1000000);
    }
    n00b_atomic_store(&overlap_first_saw_second,
                      n00b_atomic_load(&overlap_second_ran));
    n00b_atomic_store(&overlap_first_done, true);
}
#endif

static void
test_topic_requests_run_concurrently(void)
{
#ifdef N00B_DEBUG
    /* A request still in its worker must not hold up the next one on the
     * same conduit, since the next may be what releases it, as when one
     * request ends a long poll another is waiting on. */
    auto cr = n00b_conduit_new();
    n00b_conduit_t *c = n00b_result_get(cr);

    auto ta = n00b_http_request(c, n00b_string_from_cstr("ftp://a.example/"));
    auto tb = n00b_http_request(c, n00b_string_from_cstr("ftp://b.example/"));
    assert(n00b_result_is_ok(ta));
    assert(n00b_result_is_ok(tb));

    overlap_first = (n00b_conduit_topic_base_t *)n00b_result_get(ta);
    n00b_atomic_store(&overlap_second_ran, false);
    n00b_atomic_store(&overlap_first_saw_second, false);
    n00b_atomic_store(&overlap_first_done, false);
    n00b_http_test_before_response_close = overlap_hook;

    /* Reading a topic subscribes to it, which submits its request, so A's
     * worker is parked in the hook before B is submitted. */
    auto ra = n00b_conduit_read(n00b_http_response_t *, n00b_result_get(ta),
                                .timeout_ms = 60000);
    assert(n00b_result_is_ok(ra));
    auto rb = n00b_conduit_read(n00b_http_response_t *, n00b_result_get(tb),
                                .timeout_ms = 60000);
    assert(n00b_result_is_ok(rb));

    for (int i = 0; i < 60000 && !n00b_atomic_load(&overlap_first_done);
         i++) {
        base_nanosleep_ns(1000000);
    }
    assert(n00b_atomic_load(&overlap_first_done));
    if (!n00b_atomic_load(&overlap_first_saw_second)) {
        fprintf(stderr,
                "  [FAIL] the second request on a conduit ran only after the "
                "first one's worker gave up waiting for it\n");
    }
    assert(n00b_atomic_load(&overlap_first_saw_second));

    n00b_http_test_before_response_close = nullptr;
    n00b_conduit_destroy(c);
    printf("  [PASS] async requests on one conduit run concurrently\n");
#endif
}

#ifdef N00B_DEBUG
static _Atomic(bool) grow_gate_entered;
static _Atomic(bool) grow_gate_release;
static _Atomic(bool) grow_busy_started;
static _Atomic(bool) grow_busy_release;
static _Atomic(bool) grow_submit_ok;
static _Atomic(bool) grow_late_ran;

/* Hang bound only: returns as soon as `flag` is set. */
static void
grow_wait_for(_Atomic(bool) *flag)
{
    for (int i = 0; i < 60000 && !n00b_atomic_load(flag); i++) {
        base_nanosleep_ns(1000000);
    }
}

static void
grow_busy_job(void *arg)
{
    (void)arg;
    n00b_atomic_store(&grow_busy_started, true);
    grow_wait_for(&grow_busy_release);
}

static void
grow_late_job(void *arg)
{
    (void)arg;
    n00b_atomic_store(&grow_late_ran, true);
}

static void
grow_gate(n00b_conduit_service_t *svc)
{
    (void)svc;
    n00b_atomic_store(&grow_gate_entered, true);
    grow_wait_for(&grow_gate_release);
}

static void *
grow_submitter(void *raw)
{
    auto r = n00b_conduit_service_submit_grow(raw, grow_late_job, nullptr);
    n00b_atomic_store(&grow_submit_ok, n00b_result_is_ok(r));
    return nullptr;
}
#endif

static void
test_grow_never_outlives_stop(void)
{
#ifdef N00B_DEBUG
    /* A worker that submit_grow adds while the service stops must be one
     * stop joins, or must not be added at all: an unjoined worker keeps
     * running after n00b_conduit_destroy frees the service under it. The
     * hook holds the submitter after it has queued its job and decided to
     * grow, until stop returns. */
    auto cr = n00b_conduit_new();
    n00b_conduit_t *c = n00b_result_get(cr);
    auto sr = n00b_conduit_service_new(c);
    assert(n00b_result_is_ok(sr));
    n00b_conduit_service_t *svc = n00b_result_get(sr);
    assert(n00b_result_is_ok(n00b_conduit_service_start(svc)));

    n00b_atomic_store(&grow_gate_entered, false);
    n00b_atomic_store(&grow_gate_release, false);
    n00b_atomic_store(&grow_busy_started, false);
    n00b_atomic_store(&grow_busy_release, false);
    n00b_atomic_store(&grow_submit_ok, false);
    n00b_atomic_store(&grow_late_ran, false);

    assert(n00b_result_is_ok(
        n00b_conduit_service_submit(svc, grow_busy_job, nullptr)));
    grow_wait_for(&grow_busy_started);
    assert(n00b_atomic_load(&grow_busy_started));

    n00b_conduit_test_before_grow = grow_gate;
    auto tr = n00b_thread_spawn(grow_submitter, svc);
    assert(n00b_result_is_ok(tr));
    grow_wait_for(&grow_gate_entered);
    assert(n00b_atomic_load(&grow_gate_entered));

    n00b_atomic_store(&grow_busy_release, true);
    n00b_conduit_service_stop(svc);
    int threads_at_stop = n00b_atomic_load(&svc->num_threads);

    n00b_atomic_store(&grow_gate_release, true);
    n00b_thread_join(n00b_result_get(tr));
    n00b_conduit_test_before_grow = nullptr;

    int threads_after = n00b_atomic_load(&svc->num_threads);
    if (threads_after != threads_at_stop) {
        fprintf(stderr,
                "  [FAIL] submit_grow registered a worker after stop counted "
                "its threads (%d then %d)\n",
                threads_at_stop,
                threads_after);
    }
    assert(threads_after == threads_at_stop);
    /* The job was queued before stop, so the existing worker ran it before
     * exiting, and the submit reports success. */
    assert(n00b_atomic_load(&grow_late_ran));
    assert(n00b_atomic_load(&grow_submit_ok));

    n00b_conduit_destroy(c);
    printf("  [PASS] submit_grow adds no worker that stop misses\n");
#endif
}

#ifdef N00B_DEBUG
static _Atomic(int)  pair_arrived;
static _Atomic(int)  pair_returned;
static _Atomic(int)  pair_started;
static _Atomic(int)  pair_saw_other;

/* Lets a growing submitter go on once the other submitter has also reached
 * this point or has returned, so the two submits overlap. */
static void
pair_gate(n00b_conduit_service_t *svc)
{
    (void)svc;
    n00b_atomic_add(&pair_arrived, 1);
    for (int i = 0; i < 60000
                    && n00b_atomic_load(&pair_arrived) < 2
                    && n00b_atomic_load(&pair_returned) < 1;
         i++) {
        base_nanosleep_ns(1000000);
    }
}

/* Each job waits for the other to start, so they finish only if they run
 * at once. Hang bound only. */
static void
pair_job(void *arg)
{
    (void)arg;
    n00b_atomic_add(&pair_started, 1);
    for (int i = 0; i < 20000 && n00b_atomic_load(&pair_started) < 2; i++) {
        base_nanosleep_ns(1000000);
    }
    if (n00b_atomic_load(&pair_started) >= 2) {
        n00b_atomic_add(&pair_saw_other, 1);
    }
}

static void *
pair_submitter(void *raw)
{
    auto r = n00b_conduit_service_submit_grow(raw, pair_job, nullptr);
    assert(n00b_result_is_ok(r));
    n00b_atomic_add(&pair_returned, 1);
    return nullptr;
}
#endif

static void
test_concurrent_grow_gives_each_job_a_worker(void)
{
#ifdef N00B_DEBUG
    /* Two submit_grow calls racing on a service with one idle worker must
     * between them add a worker: two jobs are queued for it. Each job here
     * waits for the other, as one request can wait on another. */
    auto cr = n00b_conduit_new();
    n00b_conduit_t *c = n00b_result_get(cr);
    auto sr = n00b_conduit_service_new(c);
    assert(n00b_result_is_ok(sr));
    n00b_conduit_service_t *svc = n00b_result_get(sr);
    assert(n00b_result_is_ok(n00b_conduit_service_start(svc)));

    /* Bring up one worker and let it go idle. */
    n00b_atomic_store(&grow_late_ran, false);
    assert(n00b_result_is_ok(
        n00b_conduit_service_submit(svc, grow_late_job, nullptr)));
    grow_wait_for(&grow_late_ran);
    for (int i = 0; i < 60000; i++) {
        n00b_condition_lock(&svc->job_cv);
        int idle = svc->idle_workers;
        n00b_condition_unlock(&svc->job_cv);
        if (idle == 1) {
            break;
        }
        base_nanosleep_ns(1000000);
    }

    n00b_atomic_store(&pair_arrived, 0);
    n00b_atomic_store(&pair_returned, 0);
    n00b_atomic_store(&pair_started, 0);
    n00b_atomic_store(&pair_saw_other, 0);
    n00b_conduit_test_before_grow = pair_gate;

    auto t1 = n00b_thread_spawn(pair_submitter, svc);
    auto t2 = n00b_thread_spawn(pair_submitter, svc);
    assert(n00b_result_is_ok(t1));
    assert(n00b_result_is_ok(t2));
    n00b_thread_join(n00b_result_get(t1));
    n00b_thread_join(n00b_result_get(t2));

    for (int i = 0; i < 60000 && n00b_atomic_load(&pair_started) < 2; i++) {
        base_nanosleep_ns(1000000);
    }
    n00b_conduit_test_before_grow = nullptr;
    n00b_conduit_destroy(c);

    if (n00b_atomic_load(&pair_saw_other) != 2) {
        fprintf(stderr,
                "  [FAIL] two racing submit_grow jobs did not run at once "
                "(%d saw the other)\n",
                n00b_atomic_load(&pair_saw_other));
    }
    assert(n00b_atomic_load(&pair_saw_other) == 2);
    printf("  [PASS] racing submit_grow calls give each job a worker\n");
#endif
}

#define JOB_ROUNDS     20000
#define JOB_LEAK_BOUND (64 * 1024)

static _Atomic(int) jobs_done;

static void
count_job(void *arg)
{
    (void)arg;
    n00b_atomic_add(&jobs_done, 1);
}

static void
test_service_jobs_are_freed(void)
{
    /* Every submit allocates a job record in the conduit's pool, which the
     * GC never sweeps, so a worker that runs a job must free it. A leaked
     * record is a few dozen bytes, so JOB_ROUNDS of them map far more than
     * JOB_LEAK_BOUND; freed ones reuse the same pages. */
    auto cr = n00b_conduit_new();
    n00b_conduit_t *c = n00b_result_get(cr);
    auto sr = n00b_conduit_service_new(c);
    assert(n00b_result_is_ok(sr));
    n00b_conduit_service_t *svc = n00b_result_get(sr);
    assert(n00b_result_is_ok(n00b_conduit_service_start(svc)));

    n00b_pool_t *pool = &n00b_get_runtime()->conduit_pool;
    n00b_atomic_store(&jobs_done, 0);
    uint64_t before = n00b_pool_mapped_bytes(pool);
    for (int i = 0; i < JOB_ROUNDS; i++) {
        assert(n00b_result_is_ok(
            n00b_conduit_service_submit(svc, count_job, nullptr)));
        /* One job in flight at a time, so the pool can reuse each record. */
        for (int spin = 0; spin < 60000 && n00b_atomic_load(&jobs_done) <= i;
             spin++) {
            base_nanosleep_ns(10000);
        }
        assert(n00b_atomic_load(&jobs_done) > i);
    }
    int64_t growth = (int64_t)n00b_pool_mapped_bytes(pool) - (int64_t)before;

    n00b_conduit_destroy(c);
    if (growth > JOB_LEAK_BOUND) {
        fprintf(stderr,
                "  [FAIL] %d service jobs grew conduit_pool by %lld bytes\n",
                JOB_ROUNDS,
                (long long)growth);
    }
    assert(growth <= JOB_LEAK_BOUND);
    printf("  [PASS] service jobs are freed after they run (%lld bytes)\n",
           (long long)growth);
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
    test_topic_requests_run_concurrently();
    test_grow_never_outlives_stop();
    test_concurrent_grow_gives_each_job_a_worker();
    test_service_jobs_are_freed();
    test_topic_request_survives_caller_allocator_destroy();
    test_redirect_status_classification();
    printf("All test_http_client tests passed.\n");

    n00b_shutdown();
    return 0;
}

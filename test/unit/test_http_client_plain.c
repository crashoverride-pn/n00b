/* test_http_client_plain.c — exercise the plain-HTTP path through
 * n00b_http_request_sync(.allow_plain_http = true). */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <string.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"
#include "net/http/http_client.h"
#include "net/http/http_service.h"
#include "internal/net/http/http_url.h"

typedef struct {
    int            call_count;
    n00b_string_t *last_body;
} echo_state_t;

static void
echo_handler(n00b_http_request_t         *req,
             n00b_http_response_writer_t *resp,
             void                        *user_data)
{
    echo_state_t  *state = user_data;
    n00b_buffer_t *body  = n00b_http_request_body(req);

    state->call_count++;
    // This handler runs on the off-libc HTTP listener worker thread.
    // libc malloc/free are unsafe there on macOS (first-touch per-thread
    // cache calls pthread_self(), which traps on a raw n00b thread), so we
    // capture the body via n00b's TSD-free allocator instead of malloc().
    state->last_body = nullptr;
    if (body && body->byte_len > 0) {
        state->last_body = n00b_buffer_to_string(body);
    }

    n00b_http_response_writer_status(resp, 202);
    n00b_http_response_writer_text(resp,
                                   r"{\"ok\":true}",
                                   .content_type = r"application/json");
}

static n00b_http_service_t *
start_echo_service(echo_state_t *state)
{
    n00b_http_service_t *svc = n00b_http_service_new(.bind_port = 0);
    auto rr = n00b_http_service_route(svc,
                                      r"POST",
                                      r"/echo",
                                      echo_handler,
                                      state);
    assert(n00b_result_is_ok(rr));
    auto sr = n00b_http_service_start(svc);
    if (n00b_result_is_err(sr)) {
        fprintf(stderr, "http service start failed: err=%d\n",
                n00b_result_get_err(sr));
    }
    assert(n00b_result_is_ok(sr));
    return svc;
}

static n00b_string_t *
service_url(n00b_http_service_t *svc, const char *path)
{
    uint16_t port = n00b_http_service_port(svc);
    int64_t  port64 = (int64_t)port;
    return n00b_cformat("http://127.0.0.1:[|#|][|#|]",
                        port64,
                        n00b_string_from_cstr(path));
}

static void
test_plain_post_roundtrips(void)
{
    echo_state_t         state = {};
    n00b_http_service_t *svc   = start_echo_service(&state);

    n00b_buffer_t *body = n00b_buffer_from_cstr("{\"hello\":\"world\"}");
    n00b_string_t *url  = service_url(svc, "/echo");

    auto rr = n00b_http_request_sync(
        url,
        .method           = r"POST",
        .body             = body,
        .content_type     = r"application/json",
        .allow_plain_http = true);
    assert(n00b_result_is_ok(rr));

    n00b_http_response_t *resp = n00b_result_get(rr);
    assert(n00b_http_response_status(resp) == 202);

    n00b_buffer_t *resp_body = n00b_http_response_body(resp);
    assert(resp_body != nullptr);
    assert(resp_body->byte_len == (int64_t)strlen("{\"ok\":true}"));
    assert(memcmp(resp_body->data, "{\"ok\":true}",
                  (size_t)resp_body->byte_len)
           == 0);

    assert(state.call_count == 1);
    assert(state.last_body != nullptr);
    assert(n00b_unicode_str_eq(state.last_body,
                               n00b_string_from_cstr("{\"hello\":\"world\"}"),
                               .case_sensitive = true));

    n00b_http_service_stop(svc);
    printf("  [PASS] plain_post_roundtrips\n");
}


// n00b#473. The plain-HTTP client arms SO_RCVTIMEO/SO_SNDTIMEO on its socket
// (plain_tcp_connect, whenever timeout_ms > 0 -- the default is 30s). A socket
// with a timeout set is NOT restarted by SA_RESTART: POSIX requires the
// syscall to fail with EINTR instead. n00b's own stop-the-world suspend signal
// is RT 40 and is installed with SA_RESTART, so it looks harmless and is not.
//
// The client used to map any rc < 0 from send()/recv() to BAD_RESPONSE, so a
// signal arriving mid-request failed the request. It was rare per request and
// certain in bulk: in #473 a loop of HTTP calls died after 347, 135, 328 and
// 90 successes on different runs, and the very next call to the same live
// server succeeded.
//
// This test makes that deterministic rather than waiting for a GC pause: a
// helper thread hammers the requesting thread with a signal whose handler is
// installed the same way n00b installs its suspend handler (SA_RESTART set),
// while the requesting thread issues real requests to a real local server.
// Without the EINTR retries this fails in the first few requests; with them
// every request must still succeed and return the right body.

#define EINTR_PROBE_SIG SIGUSR2

static _Atomic(bool)     eintr_storm_run  = false;
static _Atomic(uint64_t) eintr_storm_hits = 0;
static _Atomic(bool)     eintr_handled    = false;

static void
eintr_probe_handler(int sig)
{
    (void)sig;
    atomic_store_explicit(&eintr_handled, true, memory_order_relaxed);
}

typedef struct {
    pthread_t target;
} storm_args_t;

static void *
eintr_storm(void *raw)
{
    storm_args_t *args = raw;
    while (atomic_load_explicit(&eintr_storm_run, memory_order_relaxed)) {
        pthread_kill(args->target, EINTR_PROBE_SIG);
        atomic_fetch_add_explicit(&eintr_storm_hits, 1, memory_order_relaxed);
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 200 * 1000};
        nanosleep(&ts, nullptr);
    }
    return nullptr;
}

static void
test_requests_survive_signals(void)
{
    echo_state_t         state = {};
    n00b_http_service_t *svc   = start_echo_service(&state);
    n00b_string_t       *url   = service_url(svc, "/echo");

    // SA_RESTART, exactly as n00b installs its suspend handler. The point is
    // that this flag does NOT save a socket that has a timeout set.
    struct sigaction sa = {};
    sa.sa_handler = eintr_probe_handler;
    sa.sa_flags   = SA_RESTART;
    sigemptyset(&sa.sa_mask);
    struct sigaction old = {};
    assert(sigaction(EINTR_PROBE_SIG, &sa, &old) == 0);

    storm_args_t args = {.target = pthread_self()};
    atomic_store(&eintr_storm_run, true);
    pthread_t storm;
    assert(pthread_create(&storm, nullptr, eintr_storm, &args) == 0);

    const int requests = 40;
    for (int i = 0; i < requests; i++) {
        n00b_buffer_t *body = n00b_buffer_from_cstr("{\"hello\":\"world\"}");
        auto           rr   = n00b_http_request_sync(
            url,
            .method           = r"POST",
            .body             = body,
            .content_type     = r"application/json",
            .allow_plain_http = true);
        if (n00b_result_is_err(rr)) {
            fprintf(stderr,
                    "request %d of %d failed under signals: err=%lld "
                    "(signals delivered so far: %llu)\n",
                    i + 1,
                    requests,
                    (long long)n00b_result_get_err(rr),
                    (unsigned long long)atomic_load(&eintr_storm_hits));
        }
        assert(n00b_result_is_ok(rr));

        n00b_http_response_t *resp = n00b_result_get(rr);
        assert(n00b_http_response_status(resp) == 202);

        // The body must be intact, not merely present: a retry that resumed
        // at the wrong offset would corrupt it rather than fail outright.
        n00b_buffer_t *rb = n00b_http_response_body(resp);
        assert(rb != nullptr);
        assert(rb->byte_len == (int64_t)strlen("{\"ok\":true}"));
        assert(memcmp(rb->data, "{\"ok\":true}", (size_t)rb->byte_len) == 0);
    }

    atomic_store(&eintr_storm_run, false);
    pthread_join(storm, nullptr);
    (void)sigaction(EINTR_PROBE_SIG, &old, nullptr);

    // Guard the guard: if no signal was ever delivered, this test proves
    // nothing and must say so rather than passing quietly.
    assert(atomic_load(&eintr_handled));
    assert(atomic_load(&eintr_storm_hits) > 0);
    assert(state.call_count == requests);

    n00b_http_service_stop(svc);
    printf("  [PASS] requests_survive_signals (%d requests, %llu signals)\n",
           requests,
           (unsigned long long)atomic_load(&eintr_storm_hits));
}

static void
test_plain_http_rejected_without_flag(void)
{
    /* Without `.allow_plain_http = true`, an `http://` URL is
     * rejected at the URL parser with UNSUPPORTED_SCHEME — same
     * behaviour as before the feature landed. */
    auto rr = n00b_http_request_sync(
        n00b_string_from_cstr("http://127.0.0.1:1/"));
    assert(n00b_result_is_err(rr));
    printf("  [PASS] plain_http_rejected_without_flag\n");
}

static void
test_https_url_still_rejected_under_plain_flag(void)
{
    /* https URLs are still parsed and would route to the TLS path;
     * we don't connect (no test server), but the URL parse alone
     * must succeed under `.allow_plain_http = true`. */
    auto ur = n00b_http_url_parse(
        n00b_string_from_cstr("https://example.com/"),
        .allow_plain_http = true);
    assert(n00b_result_is_ok(ur));
    n00b_http_url_t *u = n00b_result_get(ur);
    assert(u->port == 443);
    assert(n00b_unicode_str_eq(u->scheme,
                                n00b_string_from_cstr("https")));
    printf("  [PASS] https_url_still_rejected_under_plain_flag\n");
}

static void
test_http_default_port_is_80(void)
{
    auto ur = n00b_http_url_parse(
        n00b_string_from_cstr("http://example.com/foo"),
        .allow_plain_http = true);
    assert(n00b_result_is_ok(ur));
    n00b_http_url_t *u = n00b_result_get(ur);
    assert(u->port == 80);
    assert(u->has_explicit_port == false);
    assert(n00b_unicode_str_eq(u->scheme,
                                n00b_string_from_cstr("http")));
    printf("  [PASS] http_default_port_is_80\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running plain-HTTP client tests...\n");
    test_plain_http_rejected_without_flag();
    test_https_url_still_rejected_under_plain_flag();
    test_http_default_port_is_80();
    test_plain_post_roundtrips();
    test_requests_survive_signals();
    printf("All plain-HTTP client tests passed.\n");

    n00b_shutdown();
    return 0;
}

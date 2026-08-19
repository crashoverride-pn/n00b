/*
 * test_http_proxy_https_plaintext.c — regression for grouped-005,
 * "HTTPS proxy URLs use plaintext CONNECT".
 *
 * `HTTPS_PROXY=https://...` names a TLS-only proxy: the client must start
 * a TLS handshake to the proxy itself before it ever sends CONNECT bytes.
 * Before the fix, src/net/http/http_proxy.c treated an `https://` proxy
 * URL exactly like an `http://` one (only the default port changed), so
 * src/conduit/xform_tls.c's CONNECT tunnel sent a plaintext
 * "CONNECT host:port HTTP/1.1" request — plus any Basic
 * Proxy-Authorization credential — straight to what was configured as a
 * TLS-only proxy endpoint.
 *
 * The fix flags `https://` proxy URLs via the new
 * n00b_http_proxy_route_t.requires_tls field; h1_tls_connect() (the only
 * place that dials a resolved proxy) checks it and returns
 * N00B_HTTP_ERR_PROXY_TLS_UNSUPPORTED before opening a socket at all.
 *
 * This test runs the real h1 proxy-resolution + connect path against a
 * loopback listener standing in for the configured TLS-only proxy, and
 * proves the listener never receives a connection — let alone plaintext
 * CONNECT / Proxy-Authorization bytes.
 */

#define N00B_USE_INTERNAL_API
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/env.h"
#include "adt/result.h"
#include "internal/net/http/http_url.h"
#include "internal/net/http/http_h1.h"

typedef struct {
    int      fd;
    uint16_t port;
    bool     accepted;   /* did a client connect at all? */
    uint8_t  first[1024];
    ssize_t  first_len;  /* -1 if never received (no connection, or
                          * connection closed with zero bytes read) */
} capture_server_t;

static n00b_string_t *
S(const char *s)
{
    return n00b_string_from_cstr(s);
}

static void
setenv_n(const char *name, const char *value)
{
    bool ok = n00b_putenv(S(name), S(value));
    assert(ok);
}

static void
clear_proxy_env(void)
{
    setenv_n("http_proxy", "");
    setenv_n("HTTP_PROXY", "");
    setenv_n("https_proxy", "");
    setenv_n("HTTPS_PROXY", "");
    setenv_n("no_proxy", "");
    setenv_n("NO_PROXY", "");
}

/* Bounded: accept() gets at most 800ms via select() first, so a fixed
 * (reject-before-dial) client that never connects doesn't hang the test. */
static void *
capture_thread(void *arg)
{
    capture_server_t *srv = arg;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(srv->fd, &rfds);
    struct timeval tv = {.tv_sec = 0, .tv_usec = 800 * 1000};
    int sel = select(srv->fd + 1, &rfds, nullptr, nullptr, &tv);
    if (sel <= 0) {
        return nullptr; /* no client ever connected — the expected result
                          * once the fix rejects before dialing */
    }

    int cfd = accept(srv->fd, nullptr, nullptr);
    if (cfd < 0) {
        return nullptr;
    }
    srv->accepted = true;

    struct timeval rtv = {.tv_sec = 1, .tv_usec = 0};
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
    srv->first_len = recv(cfd, srv->first, sizeof(srv->first), 0);
    close(cfd);
    return nullptr;
}

static bool
contains_bytes(const uint8_t *hay, ssize_t hay_len, const char *needle)
{
    size_t needle_len = strlen(needle);
    if (hay_len < 0 || (size_t)hay_len < needle_len) {
        return false;
    }
    for (size_t i = 0; i + needle_len <= (size_t)hay_len; i++) {
        if (memcmp(hay + i, needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_http_proxy_https_plaintext:\n");

    capture_server_t srv = {.fd = -1, .first_len = -1};
    srv.fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(srv.fd >= 0);

    int one = 1;
    setsockopt(srv.fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(0);
    assert(bind(srv.fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(srv.fd, 1) == 0);

    socklen_t alen = sizeof(addr);
    assert(getsockname(srv.fd, (struct sockaddr *)&addr, &alen) == 0);
    srv.port = ntohs(addr.sin_port);

    pthread_t tid;
    assert(pthread_create(&tid, nullptr, capture_thread, &srv) == 0);

    clear_proxy_env();
    char proxy[256];
    snprintf(proxy, sizeof(proxy),
             "https://alice:s3cr3t@127.0.0.1:%u", (unsigned)srv.port);
    setenv_n("HTTPS_PROXY", proxy);

    auto ur = n00b_http_url_parse(S("https://api.example.com/probe"));
    assert(n00b_result_is_ok(ur));

    auto rr = n00b_http_h1_round_trip(n00b_result_get(ur), .timeout_ms = 650);

    pthread_join(tid, nullptr);
    close(srv.fd);

    assert(n00b_result_is_err(rr));
    int32_t err = (int32_t)n00b_result_get_err(rr);

    printf("  proxy=%s\n", proxy);
    printf("  round_trip_err=%d\n", err);
    printf("  listener_accepted=%s first_len=%zd\n",
           srv.accepted ? "yes" : "no", srv.first_len);

    /* The fixed behavior: reject before dialing at all. */
    assert(err == N00B_HTTP_ERR_PROXY_TLS_UNSUPPORTED);
    assert(srv.accepted == false);

    /* Even if some future refactor changes the fast-reject into a late
     * one, the guarantee that must never regress is: no plaintext
     * CONNECT and no plaintext Proxy-Authorization credential ever hits
     * the wire for an https:// proxy URL. */
    assert(!contains_bytes(srv.first, srv.first_len, "CONNECT "));
    assert(!contains_bytes(srv.first, srv.first_len,
                           "Proxy-Authorization: Basic YWxpY2U6czNjcjN0"));

    printf("  [PASS] https:// proxy URL rejected before dialing — "
           "no plaintext CONNECT or credential ever reached the proxy\n");
    printf("All test_http_proxy_https_plaintext tests passed.\n");

    n00b_shutdown();
    return 0;
}

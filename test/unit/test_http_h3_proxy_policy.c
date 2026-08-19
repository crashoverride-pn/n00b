/*
 * test_http_h3_proxy_policy.c — regression for the default-H3 proxy
 * bypass half of grouped-003, "Proxy policy bypassed by direct
 * transports".
 *
 * n00b_http_request_sync() defaults to prefer_h3=true. Before the fix,
 * dispatch_once() (src/net/http/http_client.c) tried
 * n00b_http_h3_round_trip() first regardless of proxy configuration; that
 * transport dials the origin directly over QUIC/UDP and has no CONNECT
 * proxy support (unlike the h1 path, which resolves HTTP_PROXY /
 * HTTPS_PROXY in h1_tls_connect()). A caller who set HTTPS_PROXY and took
 * the default prefer_h3=true would therefore have their request sent
 * straight to the origin before proxy policy was ever consulted.
 *
 * The fix makes dispatch_once() skip the H3 attempt whenever a proxy
 * route applies to the target URL, falling through to the proxy-aware h1
 * path instead. This test proves that: with HTTPS_PROXY pointed at a
 * loopback fake CONNECT proxy and prefer_h3 left at its default (true),
 * the proxy observes a CONNECT request for the origin — meaning the
 * dispatcher routed through h1-via-proxy rather than dialing the origin
 * directly over H3.
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
#include "net/http/http_client.h"

typedef struct {
    int      fd;
    uint16_t port;
    bool     accepted;
    char     first_line[256];
    bool     have_first_line;
} fake_proxy_t;

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

/* Bounded fake CONNECT proxy: at most one client, bounded accept + recv,
 * records the first request line and exits. Never replies — this test
 * only needs to prove the CONNECT request arrived, not complete a full
 * tunnel. */
static void *
fake_proxy_thread(void *arg)
{
    fake_proxy_t *srv = arg;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(srv->fd, &rfds);
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    int sel = select(srv->fd + 1, &rfds, nullptr, nullptr, &tv);
    if (sel <= 0) {
        return nullptr;
    }

    int cfd = accept(srv->fd, nullptr, nullptr);
    if (cfd < 0) {
        return nullptr;
    }
    srv->accepted = true;

    struct timeval rtv = {.tv_sec = 1, .tv_usec = 0};
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));

    char    buf[512];
    ssize_t n = recv(cfd, buf, sizeof(buf) - 1, 0);
    close(cfd);
    if (n <= 0) {
        return nullptr;
    }
    buf[n] = '\0';

    /* First request line, up to CRLF. */
    char *eol = strstr(buf, "\r\n");
    size_t len = eol ? (size_t)(eol - buf) : strlen(buf);
    if (len >= sizeof(srv->first_line)) {
        len = sizeof(srv->first_line) - 1;
    }
    memcpy(srv->first_line, buf, len);
    srv->first_line[len] = '\0';
    srv->have_first_line = true;
    return nullptr;
}

static void
test_default_h3_defers_to_proxy(void)
{
    fake_proxy_t srv = {.fd = -1};
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
    assert(pthread_create(&tid, nullptr, fake_proxy_thread, &srv) == 0);

    clear_proxy_env();
    char proxy[128];
    snprintf(proxy, sizeof(proxy), "http://127.0.0.1:%u", (unsigned)srv.port);
    setenv_n("HTTPS_PROXY", proxy);

    /* Make sure an earlier test in the same process can't have poisoned
     * the H3 loss cache for this origin and force an h1 fallback for
     * the wrong reason. */
    n00b_http_loss_cache_reset();

    /* Default prefer_h3 = true — deliberately not overridden, since that
     * default is exactly the behavior under test. The origin host is
     * unroutable (RFC 2606 .invalid) so the call itself is expected to
     * fail; what matters is whether the fake proxy saw CONNECT first. */
    auto rr = n00b_http_request_sync(
        S("https://n00b-test-h3-origin.invalid:9443/probe"),
        .timeout_ms      = 300,
        .h3_handshake_ms = 200);
    (void)rr;

    pthread_join(tid, nullptr);
    close(srv.fd);

    printf("  proxy=%s\n", proxy);
    printf("  proxy_accepted=%s first_line=\"%s\"\n",
           srv.accepted ? "yes" : "no",
           srv.have_first_line ? srv.first_line : "(none)");

    assert(srv.accepted);
    assert(srv.have_first_line);
    assert(strcmp(srv.first_line,
                  "CONNECT n00b-test-h3-origin.invalid:9443 HTTP/1.1") == 0);

    printf("  [PASS] default prefer_h3=true with HTTPS_PROXY set routes "
           "through the proxy-aware h1 CONNECT path instead of dialing "
           "the origin directly over H3\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_http_h3_proxy_policy:\n");
    test_default_h3_defers_to_proxy();
    printf("All test_http_h3_proxy_policy tests passed.\n");

    n00b_shutdown();
    return 0;
}

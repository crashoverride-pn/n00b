/*
 * test_http_h1_mtls_proxy_policy.c — regression for the H1-mTLS proxy
 * bypass (grouped-003, HTTP/1 half).
 *
 * `n00b_http_h1_round_trip()` only resolves HTTP_PROXY/HTTPS_PROXY on the
 * conduit-TLS path (src/net/http/http_h1.c: h1_tls_connect). Requests that
 * carry mTLS client-cert auth fall through to the legacy acme_tls
 * transport, which dials the origin host directly and has no proxy CONNECT
 * support. Left unchecked, a caller who sets HTTPS_PROXY and also passes
 * mTLS auth would have their request silently bypass the configured
 * proxy (skipping proxy logging/auth/egress controls) and dial the origin
 * straight away.
 *
 * The fix (see n00b_http_h1_round_trip in http_h1.c) fails closed: when a
 * proxy route applies to the URL and the request carries mTLS auth, the
 * round trip returns N00B_HTTP_ERR_PROXY_MTLS_UNSUPPORTED before opening
 * any socket, rather than silently connecting straight to the origin.
 *
 * No real certificate material or network access is needed: the mTLS
 * gate in n00b_http_h1_round_trip only checks that the auth pointers are
 * non-null (it never dereferences the key/cert bytes before our new
 * proxy check runs), so a dummy non-null n00b_quic_secret_t pointer is
 * enough to exercise the code path under test.
 */

#define N00B_USE_INTERNAL_API
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/env.h"
#include "adt/result.h"
#include "internal/net/http/http_url.h"
#include "internal/net/http/http_h1.h"
#include "net/http/http_auth.h"

static n00b_string_t *
S(const char *cstr)
{
    return n00b_string_from_cstr(cstr);
}

static void
setenv_n(const char *name, const char *value)
{
    bool ok = n00b_putenv(S(name), S(value));
    assert(ok);
}

/* Mirrors test_http_proxy.c's clear_proxy_env — empty-string "unsets"
 * every proxy var this module reads so tests don't inherit the ambient
 * shell's environment. */
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

static n00b_http_url_t *
parse_url(const char *url)
{
    auto r = n00b_http_url_parse(S(url));
    if (n00b_result_is_err(r)) {
        fprintf(stderr, "  [FAIL] could not parse test URL <%s>\n", url);
        abort();
    }
    return n00b_result_get(r);
}

/* A dummy mTLS auth helper.  The mTLS gate in n00b_http_h1_round_trip
 * (and our new proxy-policy check right after it) only tests these
 * pointers for non-null-ness before deciding whether to fail closed —
 * it never reads through them at that point, so the bytes behind these
 * pointers are never touched. */
static n00b_http_auth_t *
dummy_mtls_auth(void)
{
    static uint8_t             fake_cert_byte;
    static size_t              fake_cert_len = 1;
    static n00b_http_auth_t    auth;
    memset(&auth, 0, sizeof(auth));
    auth.mtls_key              = (n00b_quic_secret_t *)&fake_cert_byte;
    auth.mtls_cert_chain_der   = &fake_cert_byte;
    auth.mtls_cert_chain_lens  = &fake_cert_len;
    auth.mtls_cert_chain_count = 1;
    return &auth;
}

/* Vulnerable-behavior regression: with HTTPS_PROXY configured and mTLS
 * auth on the request, the round trip must fail closed with the explicit
 * proxy-policy error instead of silently dialing the origin directly. */
static void
test_mtls_with_proxy_fails_closed(void)
{
    clear_proxy_env();
    setenv_n("HTTPS_PROXY", "http://127.0.0.1:1");

    n00b_http_url_t *url = parse_url("https://n00b-test-mtls-origin.invalid:9443/");

    auto rr = n00b_http_h1_round_trip(url,
                                      .auth       = dummy_mtls_auth(),
                                      .timeout_ms = 200);
    assert(n00b_result_is_err(rr));
    int32_t err = (int32_t)n00b_result_get_err(rr);
    assert(err == N00B_HTTP_ERR_PROXY_MTLS_UNSUPPORTED);

    printf("  [PASS] mTLS request with HTTPS_PROXY set fails closed "
           "(N00B_HTTP_ERR_PROXY_MTLS_UNSUPPORTED), no direct origin dial\n");
}

/* Control case: the same mTLS request with NO proxy configured must NOT
 * return the proxy-policy error — proving the new gate is conditional on
 * an active proxy route, not a blanket regression on all mTLS requests.
 * (It still fails, because n00b-test-mtls-origin.invalid does not
 * resolve — RFC 2606 reserved TLD — but with a different error.) */
static void
test_mtls_without_proxy_unaffected(void)
{
    clear_proxy_env();

    n00b_http_url_t *url = parse_url("https://n00b-test-mtls-origin.invalid:9443/");

    auto rr = n00b_http_h1_round_trip(url,
                                      .auth       = dummy_mtls_auth(),
                                      .timeout_ms = 200);
    assert(n00b_result_is_err(rr));
    int32_t err = (int32_t)n00b_result_get_err(rr);
    assert(err != N00B_HTTP_ERR_PROXY_MTLS_UNSUPPORTED);

    printf("  [PASS] mTLS request with no proxy configured is unaffected "
           "by the new proxy-policy gate\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_http_h1_mtls_proxy_policy:\n");
    test_mtls_with_proxy_fails_closed();
    test_mtls_without_proxy_unaffected();
    printf("All test_http_h1_mtls_proxy_policy tests passed.\n");

    n00b_shutdown();
    return 0;
}

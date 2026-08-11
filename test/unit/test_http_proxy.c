/*
 * test_http_proxy.c — HTTP_PROXY / HTTPS_PROXY / NO_PROXY resolution
 * (src/net/http/http_proxy.c) unit tests.
 *
 * Coverage:
 *   - No env vars set -> inactive (today's direct-dial behavior, unchanged)
 *   - https_proxy / HTTPS_PROXY / http_proxy / HTTP_PROXY precedence
 *   - NO_PROXY exact + subdomain-suffix matching, "*" wildcard
 *   - userinfo -> Proxy-Authorization: Basic header generation
 *   - default ports (80 for a scheme-less/http proxy value, 443 for https://)
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/env.h"
#include "adt/result.h"
#include "internal/net/http/http_url.h"
#include "internal/net/http/http_proxy.h"

static n00b_string_t *
S(const char *cstr)
{
    return n00b_string_from_cstr(cstr);
}

static bool
streq(n00b_string_t *s, const char *cstr)
{
    if (!s) {
        return cstr == nullptr;
    }
    size_t cl = strlen(cstr);
    return s->u8_bytes == cl && memcmp(s->data, cstr, cl) == 0;
}

static void
setenv_n(const char *name, const char *value)
{
    bool ok = n00b_putenv(S(name), S(value));
    assert(ok);
}

/* Empty-string clears every var this module reads, since
 * n00b_http_proxy_resolve treats an empty value as unset — there is no
 * n00b_unsetenv, and this keeps tests isolated from whatever the ambient
 * shell happened to export. */
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
https_url(const char *url)
{
    auto r = n00b_http_url_parse(S(url));
    if (n00b_result_is_err(r)) {
        fprintf(stderr, "  [FAIL] could not parse test URL <%s>\n", url);
        abort();
    }
    return n00b_result_get(r);
}

static n00b_http_url_t *
http_url(const char *url)
{
    auto r = n00b_http_url_parse(S(url), .allow_plain_http = true);
    if (n00b_result_is_err(r)) {
        fprintf(stderr, "  [FAIL] could not parse test URL <%s>\n", url);
        abort();
    }
    return n00b_result_get(r);
}

static void
test_no_env_inactive(void)
{
    clear_proxy_env();

    n00b_http_proxy_route_t route = n00b_http_proxy_resolve(https_url("https://api.example.com/v1"));
    assert(route.active == false);

    printf("  [PASS] no proxy env vars -> inactive\n");
}

static void
test_https_proxy_used(void)
{
    clear_proxy_env();
    setenv_n("HTTPS_PROXY", "http://proxy.local:3128");

    n00b_http_proxy_route_t route = n00b_http_proxy_resolve(https_url("https://api.example.com/v1"));
    assert(route.active == true);
    assert(streq(route.host, "proxy.local"));
    assert(route.port == 3128);
    assert(route.proxy_auth_header == nullptr);

    printf("  [PASS] HTTPS_PROXY used for an https target\n");
}

static void
test_http_proxy_fallback_for_https_target(void)
{
    clear_proxy_env();
    setenv_n("HTTP_PROXY", "proxy2.local:8080");

    n00b_http_proxy_route_t route = n00b_http_proxy_resolve(https_url("https://api.example.com/v1"));
    assert(route.active == true);
    assert(streq(route.host, "proxy2.local"));
    assert(route.port == 8080);

    printf("  [PASS] HTTP_PROXY used as a fallback for an https target\n");
}

static void
test_http_target_ignores_https_proxy(void)
{
    clear_proxy_env();
    setenv_n("HTTPS_PROXY", "proxy.local:3128");
    setenv_n("HTTP_PROXY", "proxy3.local:80");

    n00b_http_proxy_route_t route = n00b_http_proxy_resolve(http_url("http://api.example.com/v1"));
    assert(route.active == true);
    assert(streq(route.host, "proxy3.local"));

    printf("  [PASS] a plain-http target only consults HTTP_PROXY\n");
}

static void
test_lowercase_wins_over_uppercase(void)
{
    clear_proxy_env();
    setenv_n("https_proxy", "lower.local:1111");
    setenv_n("HTTPS_PROXY", "upper.local:2222");

    n00b_http_proxy_route_t route = n00b_http_proxy_resolve(https_url("https://api.example.com/v1"));
    assert(route.active == true);
    assert(streq(route.host, "lower.local"));
    assert(route.port == 1111);

    printf("  [PASS] lowercase https_proxy takes precedence over HTTPS_PROXY\n");
}

static void
test_no_proxy_exact_match(void)
{
    clear_proxy_env();
    setenv_n("HTTPS_PROXY", "proxy.local:3128");
    setenv_n("NO_PROXY", "api.example.com,other.example.com");

    n00b_http_proxy_route_t route = n00b_http_proxy_resolve(https_url("https://api.example.com/v1"));
    assert(route.active == false);

    printf("  [PASS] NO_PROXY exact-match excludes the host\n");
}

static void
test_no_proxy_subdomain_suffix(void)
{
    clear_proxy_env();
    setenv_n("HTTPS_PROXY", "proxy.local:3128");
    setenv_n("NO_PROXY", ".example.com");

    n00b_http_proxy_route_t excluded = n00b_http_proxy_resolve(https_url("https://api.example.com/v1"));
    assert(excluded.active == false);

    /* "notexample.com" must NOT match the ".example.com" suffix rule — a
     * bare-substring match would incorrectly exclude it. */
    n00b_http_proxy_route_t not_excluded = n00b_http_proxy_resolve(https_url("https://notexample.com/v1"));
    assert(not_excluded.active == true);

    printf("  [PASS] NO_PROXY suffix match excludes subdomains, not lookalikes\n");
}

static void
test_no_proxy_wildcard(void)
{
    clear_proxy_env();
    setenv_n("HTTPS_PROXY", "proxy.local:3128");
    setenv_n("NO_PROXY", "*");

    n00b_http_proxy_route_t route = n00b_http_proxy_resolve(https_url("https://anything.example.com/v1"));
    assert(route.active == false);

    printf("  [PASS] NO_PROXY=* disables proxying entirely\n");
}

static void
test_userinfo_produces_auth_header(void)
{
    clear_proxy_env();
    setenv_n("HTTPS_PROXY", "http://alice:s3cr3t@proxy.local:3128");

    n00b_http_proxy_route_t route = n00b_http_proxy_resolve(https_url("https://api.example.com/v1"));
    assert(route.active == true);
    assert(streq(route.host, "proxy.local"));
    assert(route.port == 3128);
    assert(route.proxy_auth_header != nullptr);
    /* base64("alice:s3cr3t") == "YWxpY2U6czNjcjN0" */
    assert(streq(route.proxy_auth_header,
                "Proxy-Authorization: Basic YWxpY2U6czNjcjN0\r\n"));

    printf("  [PASS] userinfo in the proxy URL becomes a Proxy-Authorization header\n");
}

static void
test_default_ports(void)
{
    clear_proxy_env();
    setenv_n("HTTPS_PROXY", "proxy.local");

    n00b_http_proxy_route_t plain = n00b_http_proxy_resolve(https_url("https://api.example.com/v1"));
    assert(plain.active == true);
    assert(plain.port == 80);

    clear_proxy_env();
    setenv_n("HTTPS_PROXY", "https://proxy.local");
    n00b_http_proxy_route_t secure = n00b_http_proxy_resolve(https_url("https://api.example.com/v1"));
    assert(secure.active == true);
    assert(secure.port == 443);

    printf("  [PASS] default proxy port is 80 (scheme-less/http://) or 443 (https://)\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_http_proxy:\n");
    test_no_env_inactive();
    test_https_proxy_used();
    test_http_proxy_fallback_for_https_target();
    test_http_target_ignores_https_proxy();
    test_lowercase_wins_over_uppercase();
    test_no_proxy_exact_match();
    test_no_proxy_subdomain_suffix();
    test_no_proxy_wildcard();
    test_userinfo_produces_auth_header();
    test_default_ports();
    printf("All test_http_proxy tests passed.\n");

    n00b_shutdown();
    return 0;
}
